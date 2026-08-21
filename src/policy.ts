/**
 * Agent Action Surety - Policy Engine & Envelope
 * Deny-by-default capability gates, spend caps, rate limits, and safety envelope.
 * Zero external dependencies.
 * Copyright (c) 2026 Nymrel / JalenBuilds LLC.
 */

import {
  SuretyPolicyConfig,
  ActionEnvelope,
  PolicyEvaluationResult,
  ActionCapability,
  PolicyDecision,
  InterceptorMatch,
} from './types.js';
import { SuretySandbox } from './sandbox.js';
import { CommandInterceptor } from './interceptors.js';

export class PolicyEngine {
  private config: Required<SuretyPolicyConfig>;
  private sandbox: SuretySandbox;
  private interceptor: CommandInterceptor;

  // Rate-limiting & spend state
  private actionTimestamps: number[] = [];
  private totalSpendUsd: number = 0;
  private totalTokensUsed: number = 0;

  constructor(config?: SuretyPolicyConfig) {
    this.config = {
      capabilities: config?.capabilities || ['fs:read', 'exec:read_only'],
      allowedPaths: config?.allowedPaths || [process.cwd()],
      readOnlyPaths: config?.readOnlyPaths || [],
      deniedPathPatterns: config?.deniedPathPatterns || [],
      maxSpendUsd: config?.maxSpendUsd ?? 50.0,
      maxTokens: config?.maxTokens ?? 1_000_000,
      rateLimitPerMinute: config?.rateLimitPerMinute ?? 120,
      allowDestructiveCommands: config?.allowDestructiveCommands ?? false,
      customRules: config?.customRules || [],
      hmacSecret: config?.hmacSecret || '',
      sessionId: config?.sessionId || '',
      environment: config?.environment || 'development',
    };

    this.sandbox = new SuretySandbox({
      workspaceRoots: this.config.allowedPaths,
      readOnlyRoots: this.config.readOnlyPaths,
      deniedPatterns: this.config.deniedPathPatterns,
    });

    this.interceptor = new CommandInterceptor(this.config.customRules);
  }

  public getSandbox(): SuretySandbox {
    return this.sandbox;
  }

  public getInterceptor(): CommandInterceptor {
    return this.interceptor;
  }

  public getConfig(): Readonly<Required<SuretyPolicyConfig>> {
    return this.config;
  }

  public getAccumulatedSpendUsd(): number {
    return this.totalSpendUsd;
  }

  public getAccumulatedTokens(): number {
    return this.totalTokensUsed;
  }

  /**
   * Check if a capability is granted by policy.
   */
  public hasCapability(cap: ActionCapability): boolean {
    if (this.config.capabilities.includes(cap)) {
      return true;
    }
    // Check wildcard capability family (e.g. "fs:*" covers "fs:read")
    const [family] = cap.split(':');
    const wildcard = `${family}:*` as ActionCapability;
    return this.config.capabilities.includes(wildcard);
  }

  /**
   * Rate limiting check using a 60-second sliding window.
   */
  private checkRateLimit(now: number): { allowed: boolean; count: number } {
    const oneMinuteAgo = now - 60_000;
    this.actionTimestamps = this.actionTimestamps.filter((t) => t > oneMinuteAgo);
    if (this.actionTimestamps.length >= this.config.rateLimitPerMinute) {
      return { allowed: false, count: this.actionTimestamps.length };
    }
    return { allowed: true, count: this.actionTimestamps.length };
  }

  /**
   * Determine capabilities required for a given action envelope.
   */
  public inferRequiredCapabilities(action: ActionEnvelope): ActionCapability[] {
    const caps: ActionCapability[] = [];

    switch (action.actionType) {
      case 'fs_read':
        caps.push('fs:read');
        break;

      case 'fs_write':
        caps.push('fs:write');
        break;

      case 'fs_delete':
        caps.push('fs:delete');
        break;

      case 'exec': {
        const cmd = (action.command || '').trim();
        const isDestructive = this.interceptor.isDestructive(cmd);
        if (isDestructive) {
          caps.push('exec:privileged');
        } else if (this.isReadOnlyShellCommand(cmd)) {
          caps.push('exec:read_only');
        } else {
          caps.push('exec:modify');
        }

        if (cmd.startsWith('git ')) {
          if (cmd.includes('--force') || cmd.includes(' -f')) {
            caps.push('git:force_push');
          } else if (cmd.startsWith('git push')) {
            caps.push('git:push');
          } else if (cmd.startsWith('git commit')) {
            caps.push('git:commit');
          } else {
            caps.push('git:read');
          }
        }
        break;
      }

      case 'net':
        caps.push('net:http');
        break;

      case 'db': {
        const cmd = (action.command || '').toUpperCase();
        if (cmd.includes('DROP') || cmd.includes('TRUNCATE')) {
          caps.push('db:destructive');
        } else if (cmd.includes('ALTER') || cmd.includes('CREATE')) {
          caps.push('db:schema_migrate');
        } else {
          caps.push('db:query');
        }
        break;
      }

      case 'cloud': {
        const cmd = (action.command || '').toLowerCase();
        if (cmd.includes('delete') || cmd.includes('destroy') || cmd.includes('terminate')) {
          caps.push('cloud:delete');
        } else if (cmd.includes('create') || cmd.includes('apply') || cmd.includes('provision')) {
          caps.push('cloud:provision');
        } else {
          caps.push('cloud:read');
        }
        break;
      }

      case 'git': {
        const cmd = (action.command || '').toLowerCase();
        if (cmd.includes('--force') || cmd.includes('-f')) {
          caps.push('git:force_push');
        } else if (cmd.includes('push')) {
          caps.push('git:push');
        } else if (cmd.includes('commit')) {
          caps.push('git:commit');
        } else {
          caps.push('git:read');
        }
        break;
      }

      default:
        caps.push('exec:modify');
    }

    return caps;
  }

  private isReadOnlyShellCommand(cmd: string): boolean {
    const readOnlyPrefixes = [
      'ls', 'dir', 'pwd', 'echo', 'cat', 'type', 'head', 'tail', 'grep', 'rg',
      'findstr', 'node -v', 'npm -v', 'python --version', 'git status', 'git log',
      'git diff', 'git branch', 'whoami', 'uname', 'hostname'
    ];
    const lower = cmd.toLowerCase().trim();
    return readOnlyPrefixes.some((p) => lower === p || lower.startsWith(p + ' '));
  }

  /**
   * Evaluate an action against safety policy, interceptors, sandbox, rate limits, and spend bounds.
   */
  public evaluate(action: ActionEnvelope): PolicyEvaluationResult {
    const now = action.timestamp || Date.now();
    const reasons: string[] = [];
    const violations: InterceptorMatch[] = [];
    let decision: PolicyDecision = 'ALLOW';
    let normalizedPath: string | undefined;

    // 1. Check Rate Limits
    const rateCheck = this.checkRateLimit(now);
    if (!rateCheck.allowed) {
      reasons.push(`Rate limit exceeded: ${rateCheck.count} actions performed in the last 60 seconds (limit: ${this.config.rateLimitPerMinute}/min).`);
      return {
        decision: 'DENY',
        allowed: false,
        reasons,
        violations: [],
        capabilitiesRequired: [],
        timestamp: now,
      };
    }

    // 2. Check Spend & Token Bounds
    const estimatedCost = action.estimatedCostUsd || 0;
    if (this.totalSpendUsd + estimatedCost > this.config.maxSpendUsd) {
      reasons.push(`Spend budget exceeded: requested $${estimatedCost.toFixed(4)} would exceed remaining cap of $${(this.config.maxSpendUsd - this.totalSpendUsd).toFixed(4)}.`);
      return {
        decision: 'DENY',
        allowed: false,
        reasons,
        violations: [],
        capabilitiesRequired: [],
        timestamp: now,
      };
    }

    const requestedTokens = action.tokensRequested || 0;
    if (this.totalTokensUsed + requestedTokens > this.config.maxTokens) {
      reasons.push(`Token limit exceeded: requested ${requestedTokens} tokens exceeds remaining quota of ${this.config.maxTokens - this.totalTokensUsed}.`);
      return {
        decision: 'DENY',
        allowed: false,
        reasons,
        violations: [],
        capabilitiesRequired: [],
        timestamp: now,
      };
    }

    // 3. Capability Enforcement (Deny-by-default)
    const requiredCaps = this.inferRequiredCapabilities(action);
    const missingCaps = requiredCaps.filter((cap) => !this.hasCapability(cap));

    if (missingCaps.length > 0) {
      decision = 'DENY';
      reasons.push(`Missing required capabilities: [${missingCaps.join(', ')}]. Granted capabilities: [${this.config.capabilities.join(', ')}].`);
    }

    // 4. Filesystem Path Sandbox Verification
    if (action.targetPath) {
      const isWrite = action.actionType === 'fs_write' || action.actionType === 'fs_delete';
      const pathVal = this.sandbox.validatePath(action.targetPath, isWrite);
      normalizedPath = pathVal.normalizedPath;

      if (!pathVal.allowed) {
        decision = 'DENY';
        reasons.push(pathVal.reason || `Path validation failed for "${action.targetPath}".`);
      }
    }

    // 5. Command Interceptors (Deep Pattern Inspection)
    if (action.command) {
      const matches = this.interceptor.inspect(action.command);
      if (matches.length > 0) {
        violations.push(...matches);
        const hasCritical = matches.some((m) => m.severity === 'CRITICAL');
        const hasHigh = matches.some((m) => m.severity === 'HIGH');

        if (hasCritical || (!this.config.allowDestructiveCommands && hasHigh)) {
          decision = 'DENY';
          for (const m of matches) {
            reasons.push(`[${m.category}] Blocked: ${m.ruleName} (${m.description}). Remediation: ${m.remediation || 'None'}`);
          }
        } else if (hasHigh) {
          decision = 'REQUIRE_HUMAN_APPROVAL';
          reasons.push(`High severity command requires human confirmation.`);
        }
      }
    }

    // Record usage if approved
    const allowed = decision === 'ALLOW';
    if (allowed) {
      this.actionTimestamps.push(now);
      this.totalSpendUsd += estimatedCost;
      this.totalTokensUsed += requestedTokens;
      if (reasons.length === 0) {
        reasons.push('Action passed all surety safety gates.');
      }
    }

    return {
      decision,
      allowed,
      reasons,
      violations,
      capabilitiesRequired: requiredCaps,
      normalizedPath,
      spendApprovedUsd: allowed ? estimatedCost : 0,
      tokensApproved: allowed ? requestedTokens : 0,
      timestamp: now,
    };
  }
}
