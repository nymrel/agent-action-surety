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

const MAX_COMMAND_CHARACTERS = 32_768;
const ASCII_WHITESPACE = new Set([' ', '\t', '\n', '\r', '\f', '\v']);

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Convert the portable command-string API into one executable plus argv.
 *
 * This is deliberately smaller than a shell grammar: ASCII whitespace
 * separates arguments, single and double quotes group text, and only `\"` and
 * `\\` are escapes inside double quotes. Backslashes outside double quotes are
 * literal so Windows paths survive unchanged. The returned argv must be passed
 * to a no-shell process API such as execFile or subprocess.run(shell=False).
 */
export function parseCommandArgv(command: string): string[] {
  const characters = Array.from(command);
  if (characters.length > MAX_COMMAND_CHARACTERS) {
    throw new Error(
      `Command exceeds the ${MAX_COMMAND_CHARACTERS}-character safety limit.`
    );
  }

  const argv: string[] = [];
  let current = '';
  let quote: "'" | '"' | null = null;
  let tokenStarted = false;

  for (let index = 0; index < characters.length; index += 1) {
    const character = characters[index];
    const codePoint = character.codePointAt(0)!;
    const isWhitespace = ASCII_WHITESPACE.has(character);
    const isControl =
      codePoint <= 0x1f ||
      codePoint === 0x7f ||
      (codePoint >= 0x80 && codePoint <= 0x9f);

    if (isControl && !isWhitespace) {
      throw new Error(
        `Command contains a disallowed control character (U+${codePoint
          .toString(16)
          .toUpperCase()
          .padStart(4, '0')}).`
      );
    }

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

  if (quote !== null) {
    throw new Error('Command contains an unterminated quoted argument.');
  }

  if (tokenStarted) {
    argv.push(current);
  }

  if (argv.length === 0) {
    throw new Error('Command must include an executable.');
  }
  if (argv[0].length === 0) {
    throw new Error('Command executable must not be empty.');
  }

  return argv;
}

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
  let commandArgv: string[] | undefined;

  if (action.actionType === 'exec') {
    try {
      commandArgv = parseCommandArgv(action.command || '');
    } catch (error: unknown) {
      const evaluation: PolicyEvaluationResult = {
        decision: 'DENY',
        allowed: false,
        reasons: [`Command parsing failed closed: ${errorMessage(error)}`],
        violations: [],
        capabilitiesRequired: [],
        spendApprovedUsd: 0,
        tokensApproved: 0,
        timestamp: action.timestamp || Date.now(),
      };
      const receipt = activeLedger.recordAction(action, evaluation);
      return {
        success: false,
        evaluation,
        receipt,
        error: `Action denied by surety command parser: ${errorMessage(error)}`,
        exitCode: 1,
        executionTimeMs: Date.now() - startTime,
      };
    }
  }

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
    } catch (err: unknown) {
      return {
        success: false,
        evaluation,
        receipt,
        error: errorMessage(err),
        executionTimeMs: Date.now() - startTime,
      };
    }
  }

  // Default execution always uses the argv parsed before policy evaluation.
  if (action.actionType === 'exec' && commandArgv) {
    return new Promise((resolve) => {
      const cwd = action.workingDir || process.cwd();
      child_process.execFile(
        commandArgv[0],
        commandArgv.slice(1),
        {
          cwd,
          timeout: 30_000,
          maxBuffer: 10 * 1024 * 1024,
          windowsHide: true,
          encoding: 'utf8',
        },
        (error, stdout, stderr) => {
          const duration = Date.now() - startTime;
          if (error) {
            resolve({
              success: false,
              evaluation,
              receipt,
              output: stdout as unknown as T,
              error: stderr || error.message,
              exitCode: typeof error.code === 'number' ? error.code : 1,
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
