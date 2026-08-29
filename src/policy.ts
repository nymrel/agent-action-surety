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

const MAX_POLICY_COMMAND_CHARACTERS = 32_768;
const POLICY_ASCII_WHITESPACE = new Set([' ', '\t', '\n', '\r', '\f', '\v']);
const SIMPLE_READ_ONLY_EXECUTABLES = new Set([
  'ls', 'dir', 'pwd', 'echo', 'cat', 'type', 'head', 'tail', 'grep', 'findstr',
  'whoami', 'uname',
]);
const GIT_GLOBAL_OPTIONS_WITH_VALUES = new Set([
  '-c', '-C', '--config-env', '--git-dir', '--work-tree', '--namespace',
  '--super-prefix',
]);
const GIT_GLOBAL_FLAG_OPTIONS = new Set([
  '-p', '--paginate', '--no-pager', '--bare', '--no-replace-objects',
  '--literal-pathspecs', '--glob-pathspecs', '--noglob-pathspecs',
  '--icase-pathspecs', '--no-optional-locks', '--version', '--help',
]);
const GIT_READ_ONLY_SUBCOMMANDS = new Set([
  'annotate', 'blame', 'cat-file', 'count-objects', 'describe', 'diff',
  'diff-files', 'diff-index', 'diff-tree', 'for-each-ref', 'log', 'ls-files',
  'ls-remote', 'ls-tree', 'merge-base', 'name-rev', 'rev-list', 'rev-parse',
  'shortlog', 'show', 'show-branch', 'status', 'version',
]);

/** Mirror the public portable argv grammar so capability inference fails closed. */
function parsePolicyCommandArgv(command: string): string[] | null {
  const characters = Array.from(command);
  if (characters.length > MAX_POLICY_COMMAND_CHARACTERS) return null;

  const argv: string[] = [];
  let current = '';
  let quote: "'" | '"' | null = null;
  let tokenStarted = false;

  for (let index = 0; index < characters.length; index += 1) {
    const character = characters[index];
    const codePoint = character.codePointAt(0)!;
    const isWhitespace = POLICY_ASCII_WHITESPACE.has(character);
    const isControl =
      codePoint <= 0x1f ||
      codePoint === 0x7f ||
      (codePoint >= 0x80 && codePoint <= 0x9f);
    if (isControl && !isWhitespace) return null;

    if (quote === null) {
      if (isWhitespace) {
        if (tokenStarted) {
          argv.push(current);
          current = '';
          tokenStarted = false;
        }
        continue;
      }
      if (character === "'" || character === '"') {
        quote = character;
        tokenStarted = true;
        continue;
      }
      current += character;
      tokenStarted = true;
      continue;
    }

    if (character === quote) {
      quote = null;
      continue;
    }
    if (
      quote === '"' &&
      character === '\\' &&
      index + 1 < characters.length &&
      (characters[index + 1] === '"' || characters[index + 1] === '\\')
    ) {
      current += characters[index + 1];
      tokenStarted = true;
      index += 1;
      continue;
    }
    current += character;
    tokenStarted = true;
  }

  if (quote !== null) return null;
  if (tokenStarted) argv.push(current);
  if (argv.length === 0 || argv[0].length === 0) return null;
  return argv;
}

function ripgrepArgumentCanSpawnHelper(argument: string): boolean {
  const lower = argument.toLowerCase();
  if (
    lower === '--pre' ||
    lower.startsWith('--pre=') ||
    lower === '--pre-glob' ||
    lower.startsWith('--pre-glob=') ||
    lower === '--hostname-bin' ||
    lower.startsWith('--hostname-bin=') ||
    lower === '--search-zip' ||
    lower.startsWith('--search-zip=')
  ) {
    return true;
  }
  return /^-[^-]*z/.test(lower);
}

function commandContainsShellSyntax(command: string): boolean {
  return /[\r\n;&|<>()`]/.test(command) || command.includes('$(') || command.includes('${');
}

function isReadOnlyCommandArgv(argv: string[]): boolean {
  const executable = argv[0].toLowerCase();
  const args = argv.slice(1);

  if (SIMPLE_READ_ONLY_EXECUTABLES.has(executable)) return true;
  if (executable === 'hostname') return args.length === 0;
  if (executable === 'node') {
    return args.length === 1 && (args[0] === '-v' || args[0] === '--version');
  }
  if (executable === 'rg') {
    // Requiring --no-config in the first argument position prevents it from
    // being reinterpreted as an option value or a positional after `--`.
    return args[0]?.toLowerCase() === '--no-config' &&
      !args.some(ripgrepArgumentCanSpawnHelper);
  }

  // Git can execute aliases, external diff/textconv helpers, fsmonitor hooks,
  // and pagers from repository, user, or environment configuration. Treat it
  // as executable modification even when the named subcommand sounds read-only.
  return false;
}

function policyExecutableBasename(executable: string): string {
  const normalized = executable.replace(/\\/g, '/');
  return normalized.slice(normalized.lastIndexOf('/') + 1).toLowerCase();
}

function findGitSubcommand(tokens: string[]): string | null {
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    const lower = token.toLowerCase();
    if (lower === '--') return null;
    if (GIT_GLOBAL_OPTIONS_WITH_VALUES.has(token) || GIT_GLOBAL_OPTIONS_WITH_VALUES.has(lower)) {
      index += 1;
      if (index >= tokens.length) return null;
      continue;
    }
    if (
      lower.startsWith('--config-env=') ||
      lower.startsWith('--git-dir=') ||
      lower.startsWith('--work-tree=') ||
      lower.startsWith('--namespace=') ||
      lower.startsWith('--super-prefix=') ||
      lower.startsWith('--exec-path=')
    ) {
      continue;
    }
    if (lower === '--exec-path' || GIT_GLOBAL_FLAG_OPTIONS.has(lower)) continue;
    if (lower.startsWith('-')) return null;
    return lower;
  }
  return null;
}

function inferGitCapability(command: string): ActionCapability {
  const argv = parsePolicyCommandArgv(command);
  if (argv === null) return 'git:force_push';

  const tokens = policyExecutableBasename(argv[0]) === 'git' ||
    policyExecutableBasename(argv[0]) === 'git.exe'
    ? argv.slice(1)
    : argv;
  const lower = tokens.map((token) => token.toLowerCase());
  const subcommand = findGitSubcommand(tokens);
  const isPush = subcommand === 'push';

  if (
    lower.some((token) =>
      token.startsWith('--force') ||
      (token.startsWith('-') && !token.startsWith('--') && token.slice(1).includes('f'))
    ) ||
    (isPush && lower.some((token) =>
      token === '--mirror' ||
      token.startsWith('--delete') ||
      (token.startsWith('-') && !token.startsWith('--') && token.slice(1).includes('d')) ||
      token === '--prune' ||
      token.startsWith('+') ||
      token.startsWith(':')
    ))
  ) {
    return 'git:force_push';
  }
  if (isPush) return 'git:push';

  if (subcommand !== null && GIT_READ_ONLY_SUBCOMMANDS.has(subcommand)) return 'git:read';

  // Unknown or locally mutating Git commands fail closed to the only local
  // mutation capability in the public taxonomy.
  return 'git:commit';
}

function gitCommandRequiresPrivileged(
  command: string,
  capability: ActionCapability,
): boolean {
  if (capability === 'git:force_push') return true;

  const argv = parsePolicyCommandArgv(command);
  if (argv === null) return true;
  const executable = policyExecutableBasename(argv[0]);
  const tokens = executable === 'git' || executable === 'git.exe' ? argv.slice(1) : argv;
  const lower = tokens.map((token) => token.toLowerCase());
  const subcommand = findGitSubcommand(tokens);

  if (subcommand === 'reset' && lower.includes('--hard')) return true;
  if (subcommand === 'clean') {
    const shortFlags = lower
      .filter((token) => token.startsWith('-') && !token.startsWith('--'))
      .join('');
    const hasForce = lower.includes('--force') || shortFlags.includes('f');
    const hasDirectories = lower.includes('-d') || shortFlags.includes('d');
    const hasIgnored = lower.includes('-x') || shortFlags.includes('x');
    if (hasForce && hasDirectories && hasIgnored) return true;
  }
  if (subcommand === 'branch') {
    const deletes = tokens.some((token) =>
      token.toLowerCase().startsWith('--delete') ||
      (token.startsWith('-') && !token.startsWith('--') && /[dD]/.test(token.slice(1)))
    );
    const protectedBranch = lower.some((token) =>
      ['main', 'master', 'prod', 'production', 'release', 'staging'].includes(token)
    );
    if (deletes && protectedBranch) return true;
  }
  return false;
}

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
        const argv = parsePolicyCommandArgv(cmd);
        const isDirectGit = argv !== null &&
          (policyExecutableBasename(argv[0]) === 'git' || policyExecutableBasename(argv[0]) === 'git.exe');
        const gitCapability = isDirectGit ? inferGitCapability(cmd) : null;
        const isDestructive = this.interceptor.isDestructive(cmd) ||
          (gitCapability !== null && gitCommandRequiresPrivileged(cmd, gitCapability));
        if (isDestructive) {
          caps.push('exec:privileged');
        } else if (this.isReadOnlyShellCommand(cmd)) {
          caps.push('exec:read_only');
        } else {
          caps.push('exec:modify');
        }

        if (gitCapability !== null) caps.push(gitCapability);
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
        const cmd = action.command || '';
        const gitCapability = inferGitCapability(cmd);
        caps.push(gitCommandRequiresPrivileged(cmd, gitCapability) ? 'exec:privileged' : 'exec:modify');
        caps.push(gitCapability);
        break;
      }

      default:
        caps.push('exec:modify');
    }

    return caps;
  }

  private isReadOnlyShellCommand(cmd: string): boolean {
    if (commandContainsShellSyntax(cmd)) return false;
    const argv = parsePolicyCommandArgv(cmd);
    return argv !== null && isReadOnlyCommandArgv(argv);
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
