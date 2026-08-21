/**
 * Agent Action Surety - Dual-Language Execution Firewall & Safety Policy Envelope
 * Zero-dependency, tamper-evident security envelope for AI coding agents.
 * Copyright (c) 2026 Nymrel / JalenBuilds LLC.
 */

import * as child_process from 'node:child_process';
import {
  ActionEnvelope,
  ExecutionResult,
  PolicyEvaluationResult,
  ActionReceipt,
  SuretyPolicyConfig,
} from './types.js';
import { PolicyEngine } from './policy.js';
import { SuretySandbox } from './sandbox.js';
import { CommandInterceptor } from './interceptors.js';
import { ExecutionLedger } from './ledger.js';

export * from './types.js';
export { PolicyEngine } from './policy.js';
export { SuretySandbox } from './sandbox.js';
export { CommandInterceptor } from './interceptors.js';
export { ExecutionLedger } from './ledger.js';

/**
 * Quick evaluation of an action against a policy config or engine.
 */
export function evaluatePolicy(
  policyOrConfig: PolicyEngine | SuretyPolicyConfig,
  action: ActionEnvelope
): PolicyEvaluationResult {
  const engine = policyOrConfig instanceof PolicyEngine
    ? policyOrConfig
    : new PolicyEngine(policyOrConfig);
  return engine.evaluate(action);
}

/**
 * Create a standalone cryptographic receipt for an action evaluation.
 */
export function createReceipt(
  action: ActionEnvelope,
  evaluation: PolicyEvaluationResult,
  ledgerOrSecret?: ExecutionLedger | string
): ActionReceipt {
  let ledger: ExecutionLedger;
  if (ledgerOrSecret instanceof ExecutionLedger) {
    ledger = ledgerOrSecret;
  } else {
    ledger = new ExecutionLedger({ hmacSecret: ledgerOrSecret });
  }
  return ledger.recordAction(action, evaluation);
}

/**
 * Wrap and safely execute an action through the policy envelope, sandbox,
 * interceptors, and cryptographic receipt ledger.
 */
export async function wrapExecution<T = unknown>(
  engine: PolicyEngine,
  action: ActionEnvelope,
  ledger?: ExecutionLedger,
  executor?: (envelope: ActionEnvelope, evaluation: PolicyEvaluationResult) => Promise<T> | T
): Promise<ExecutionResult<T>> {
  const activeLedger = ledger || new ExecutionLedger({
    sessionId: engine.getConfig().sessionId,
    hmacSecret: engine.getConfig().hmacSecret,
  });

  const startTime = Date.now();
  const evaluation = engine.evaluate(action);
  const receipt = activeLedger.recordAction(action, evaluation);

  if (!evaluation.allowed) {
    return {
      success: false,
      evaluation,
      receipt,
      error: `Action denied by surety policy: ${evaluation.reasons.join(' | ')}`,
      executionTimeMs: Date.now() - startTime,
    };
  }

  // If custom executor callback was supplied, call it
  if (executor) {
    try {
      const output = await executor(action, evaluation);
      return {
        success: true,
        evaluation,
        receipt,
        output,
        executionTimeMs: Date.now() - startTime,
      };
    } catch (err: any) {
      return {
        success: false,
        evaluation,
        receipt,
        error: err?.message || String(err),
        executionTimeMs: Date.now() - startTime,
      };
    }
  }

  // Default shell command execution if action is 'exec' and command exists
  if (action.actionType === 'exec' && action.command) {
    return new Promise((resolve) => {
      const cwd = action.workingDir || process.cwd();
      child_process.exec(
        action.command!,
        { cwd, timeout: 30_000, maxBuffer: 10 * 1024 * 1024 },
        (error, stdout, stderr) => {
          const duration = Date.now() - startTime;
          if (error) {
            resolve({
              success: false,
              evaluation,
              receipt,
              output: stdout as unknown as T,
              error: stderr || error.message,
              exitCode: error.code || 1,
              executionTimeMs: duration,
            });
          } else {
            resolve({
              success: true,
              evaluation,
              receipt,
              output: stdout as unknown as T,
              exitCode: 0,
              executionTimeMs: duration,
            });
          }
        }
      );
    });
  }

  return {
    success: true,
    evaluation,
    receipt,
    executionTimeMs: Date.now() - startTime,
  };
}
