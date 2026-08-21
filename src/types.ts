/**
 * Agent Action Surety - Core Type Definitions
 * Zero-dependency, dual-language execution firewall & safety envelope.
 * Copyright (c) 2026 Nymrel / JalenBuilds LLC.
 */

export type ActionCapability =
  | 'fs:read'
  | 'fs:write'
  | 'fs:delete'
  | 'exec:read_only'
  | 'exec:modify'
  | 'exec:network'
  | 'exec:privileged'
  | 'net:http'
  | 'net:dns'
  | 'net:raw'
  | 'db:query'
  | 'db:schema_migrate'
  | 'db:destructive'
  | 'cloud:read'
  | 'cloud:provision'
  | 'cloud:delete'
  | 'git:read'
  | 'git:commit'
  | 'git:push'
  | 'git:force_push';

export type ActionType = 'fs_read' | 'fs_write' | 'fs_delete' | 'exec' | 'net' | 'db' | 'cloud' | 'git';

export type PolicyDecision = 'ALLOW' | 'DENY' | 'REQUIRE_HUMAN_APPROVAL';

export type InterceptorCategory = 'SHELL' | 'SQL' | 'GIT' | 'CLOUD' | 'KUBERNETES' | 'PACKAGE_MGR';

export interface InterceptorRule {
  id: string;
  name: string;
  category: InterceptorCategory;
  description: string;
  pattern: RegExp | ((command: string) => boolean);
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  remediation?: string;
}

export interface InterceptorMatch {
  ruleId: string;
  ruleName: string;
  category: InterceptorCategory;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  matchedText?: string;
  remediation?: string;
}

export interface ActionEnvelope {
  id?: string;
  actionType: ActionType;
  command?: string;
  targetPath?: string;
  content?: string;
  workingDir?: string;
  estimatedCostUsd?: number;
  tokensRequested?: number;
  metadata?: Record<string, unknown>;
  timestamp?: number;
}

export interface SuretyPolicyConfig {
  capabilities?: ActionCapability[];
  allowedPaths?: string[];
  readOnlyPaths?: string[];
  deniedPathPatterns?: string[];
  maxSpendUsd?: number;
  maxTokens?: number;
  rateLimitPerMinute?: number;
  allowDestructiveCommands?: boolean;
  customRules?: InterceptorRule[];
  hmacSecret?: string;
  sessionId?: string;
  environment?: 'development' | 'staging' | 'production';
}

export interface PolicyEvaluationResult {
  decision: PolicyDecision;
  allowed: boolean;
  reasons: string[];
  violations: InterceptorMatch[];
  capabilitiesRequired: ActionCapability[];
  normalizedPath?: string;
  spendApprovedUsd?: number;
  tokensApproved?: number;
  timestamp: number;
}

export interface ActionReceipt {
  receiptId: string;
  sessionId: string;
  actionId: string;
  actionType: ActionType;
  decision: PolicyDecision;
  commandSummary?: string;
  targetPath?: string;
  violationsCount: number;
  prevReceiptHash: string;
  receiptHash: string;
  signature?: string;
  timestamp: number;
  metadata?: Record<string, unknown>;
}

export interface ExecutionResult<T = unknown> {
  success: boolean;
  evaluation: PolicyEvaluationResult;
  receipt: ActionReceipt;
  output?: T;
  error?: string;
  exitCode?: number;
  executionTimeMs?: number;
}
