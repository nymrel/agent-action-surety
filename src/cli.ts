/**
 * Agent Action Surety - CLI Engine
 * Command line firewall wrapper and policy validator.
 * Zero external dependencies.
 * Copyright (c) 2026 Nymrel / JalenBuilds LLC.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { PolicyEngine } from './policy.js';
import { ExecutionLedger } from './ledger.js';
import { wrapExecution } from './index.js';
import { ActionReceipt, ActionEnvelope } from './types.js';

export function parseCliArgs(args: string[]) {
  const flags: Record<string, string | boolean> = {};
  const positional: string[] = [];

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith('--')) {
      const key = arg.slice(2);
      if (i + 1 < args.length && !args[i + 1].startsWith('--')) {
        flags[key] = args[i + 1];
        i++;
      } else {
        flags[key] = true;
      }
    } else if (arg.startsWith('-') && arg.length > 1) {
      const key = arg.slice(1);
      if (i + 1 < args.length && !args[i + 1].startsWith('-')) {
        flags[key] = args[i + 1];
        i++;
      } else {
        flags[key] = true;
      }
    } else {
      positional.push(arg);
    }
  }

  return { flags, positional };
}

export function printHelp(): void {
  console.log(`
========================================================================
 AGENT ACTION SURETY (CLI Firewall & Policy Envelope)
 Parent Organization: Nymrel -> JalenBuilds LLC
========================================================================

USAGE:
  agent-surety exec --cmd "<command>" [options]
  agent-surety check --cmd "<command>" [options]
  agent-surety path --target "<path>" [--write] [options]
  agent-surety verify-receipt --file <receipt.json> [--secret <key>]
  agent-surety verify-ledger --file <ledger.jsonl> [--secret <key>]

COMMANDS:
  exec             Evaluate command against surety policy and execute if allowed
  check            Dry-run evaluate command without execution
  path             Validate filesystem path against sandbox boundaries
  verify-receipt   Cryptographically verify a single action receipt
  verify-ledger    Cryptographically verify an entire Merkle hash chain

OPTIONS:
  --cmd, -c        Command string to evaluate / execute
  --target, -t     Target path for filesystem checks
  --write, -w      Indicate if path operation is a write/delete
  --allowed-paths  Comma-separated allowed root directories (default: cwd)
  --read-only      Comma-separated read-only paths
  --spend-cap      Max spend cap in USD (default: 50.0)
  --rate-limit     Max actions per minute (default: 120)
  --allow-destructive  Explicitly permit dangerous commands (disabled by default)
  --secret         HMAC secret key for signing / verifying receipts
  --json           Format output as JSON
  --help, -h       Display this help message
`);
}

export async function runCli(argv: string[] = process.argv.slice(2)): Promise<number> {
  const { flags, positional } = parseCliArgs(argv);
  const command = positional[0]?.toLowerCase() || (flags.help || flags.h ? 'help' : 'help');

  if (command === 'help' || flags.help || flags.h) {
    printHelp();
    return 0;
  }

  const asJson = Boolean(flags.json);
  const hmacSecret = typeof flags.secret === 'string' ? flags.secret : undefined;
  const allowDestructive = Boolean(flags['allow-destructive']);

  const allowedPaths = typeof flags['allowed-paths'] === 'string'
    ? flags['allowed-paths'].split(',').map((s) => s.trim())
    : [process.cwd()];

  const readOnlyPaths = typeof flags['read-only'] === 'string'
    ? flags['read-only'].split(',').map((s) => s.trim())
    : [];

  const engine = new PolicyEngine({
    capabilities: [
      'fs:read',
      'fs:write',
      'exec:read_only',
      'exec:modify',
      ...(allowDestructive ? ['exec:privileged' as const, 'cloud:delete' as const, 'git:force_push' as const] : []),
    ],
    allowedPaths,
    readOnlyPaths,
    allowDestructiveCommands: allowDestructive,
    hmacSecret,
  });

  const ledger = new ExecutionLedger({ hmacSecret });

  if (command === 'check') {
    const cmdStr = (flags.cmd || flags.c || positional.slice(1).join(' ')) as string;
    if (!cmdStr) {
      console.error('Error: --cmd is required for "check".');
      return 1;
    }

    const action: ActionEnvelope = { actionType: 'exec', command: cmdStr };
    const evaluation = engine.evaluate(action);
    const receipt = ledger.recordAction(action, evaluation);

    if (asJson) {
      console.log(JSON.stringify({ evaluation, receipt }, null, 2));
    } else {
      console.log('\n[AGENT ACTION SURETY EVALUATION]');
      console.log(`Command:  ${cmdStr}`);
      console.log(`Decision: ${evaluation.decision}`);
      console.log(`Allowed:  ${evaluation.allowed ? 'YES (SAFE)' : 'NO (BLOCKED)'}`);
      if (evaluation.reasons.length > 0) {
        console.log('Reasons:');
        evaluation.reasons.forEach((r) => console.log(`  - ${r}`));
      }
      if (evaluation.violations.length > 0) {
        console.log('Violations:');
        evaluation.violations.forEach((v) => console.log(`  - [${v.category}] ${v.ruleName} (${v.severity})`));
      }
      console.log(`Receipt Hash: ${receipt.receiptHash}\n`);
    }

    return evaluation.allowed ? 0 : 1;
  }

  if (command === 'exec') {
    const cmdStr = (flags.cmd || flags.c || positional.slice(1).join(' ')) as string;
    if (!cmdStr) {
      console.error('Error: --cmd is required for "exec".');
      return 1;
    }

    const action: ActionEnvelope = { actionType: 'exec', command: cmdStr, workingDir: process.cwd() };
    const result = await wrapExecution(engine, action, ledger);

    if (asJson) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      if (!result.success) {
        console.error('\n[SURETY FIREWALL: EXECUTION BLOCKED]');
        console.error(`Command:   ${cmdStr}`);
        console.error(`Error:     ${result.error}`);
        if (result.evaluation.violations.length > 0) {
          console.error('Violations:');
          result.evaluation.violations.forEach((v) => {
            console.error(`  - [${v.category}] ${v.ruleName} (${v.severity}): ${v.description}`);
            if (v.remediation) console.error(`    Remediation: ${v.remediation}`);
          });
        }
        console.error(`Receipt Hash: ${result.receipt.receiptHash}\n`);
        return 1;
      } else {
        if (result.output) {
          process.stdout.write(String(result.output));
        }
        console.log(`\n[SURETY: SUCCESS] (Receipt: ${result.receipt.receiptHash.slice(0, 16)}... | Time: ${result.executionTimeMs}ms)`);
      }
    }
    return result.exitCode ?? (result.success ? 0 : 1);
  }

  if (command === 'path') {
    const target = (flags.target || flags.t || positional[1]) as string;
    if (!target) {
      console.error('Error: --target is required for "path".');
      return 1;
    }

    const isWrite = Boolean(flags.write || flags.w);
    const action: ActionEnvelope = {
      actionType: isWrite ? 'fs_write' : 'fs_read',
      targetPath: target,
    };
    const evaluation = engine.evaluate(action);
    const receipt = ledger.recordAction(action, evaluation);

    if (asJson) {
      console.log(JSON.stringify({ evaluation, receipt }, null, 2));
    } else {
      console.log('\n[SURETY PATH VALIDATION]');
      console.log(`Target:    ${target}`);
      console.log(`Operation: ${isWrite ? 'WRITE' : 'READ'}`);
      console.log(`Allowed:   ${evaluation.allowed ? 'YES (WITHIN SANDBOX)' : 'NO (RESTRICTED)'}`);
      if (evaluation.reasons.length > 0) {
        evaluation.reasons.forEach((r) => console.log(`  - ${r}`));
      }
      console.log(`Receipt:   ${receipt.receiptHash}\n`);
    }

    return evaluation.allowed ? 0 : 1;
  }

  if (command === 'verify-receipt') {
    const file = flags.file as string;
    if (!file) {
      console.error('Error: --file is required for "verify-receipt".');
      return 1;
    }

    try {
      const content = fs.readFileSync(path.resolve(file), 'utf-8');
      const receipt: ActionReceipt = JSON.parse(content);
      const valid = ExecutionLedger.verifyReceipt(receipt, hmacSecret);

      if (asJson) {
        console.log(JSON.stringify({ valid, receiptId: receipt.receiptId }));
      } else {
        console.log(`\n[RECEIPT VERIFICATION]`);
        console.log(`Receipt ID: ${receipt.receiptId}`);
        console.log(`Valid:      ${valid ? 'VERIFIED (AUTHENTIC)' : 'FAILED (TAMPERED)'}\n`);
      }
      return valid ? 0 : 1;
    } catch (err: any) {
      console.error(`Verification error: ${err?.message || err}`);
      return 1;
    }
  }

  if (command === 'verify-ledger') {
    const file = flags.file as string;
    if (!file) {
      console.error('Error: --file is required for "verify-ledger".');
      return 1;
    }

    try {
      const content = fs.readFileSync(path.resolve(file), 'utf-8');
      const lines = content.split('\n').filter((l) => l.trim().length > 0);
      const receipts: ActionReceipt[] = lines.map((l) => JSON.parse(l));
      const result = ExecutionLedger.verifyChain(receipts, hmacSecret);

      if (asJson) {
        console.log(JSON.stringify({ ...result, count: receipts.length }));
      } else {
        console.log(`\n[LEDGER CHAIN VERIFICATION]`);
        console.log(`Total Receipts: ${receipts.length}`);
        console.log(`Chain Valid:    ${result.valid ? 'VERIFIED (TAMPER-EVIDENT MERKLE CHAIN INTACT)' : 'CORRUPTED / BROKEN'}`);
        if (!result.valid) {
          console.error(`Broken at index ${result.brokenIndex}: ${result.reason}`);
        }
        console.log();
      }
      return result.valid ? 0 : 1;
    } catch (err: any) {
      console.error(`Ledger verification error: ${err?.message || err}`);
      return 1;
    }
  }

  console.error(`Unknown command "${command}". Use --help for usage.`);
  return 1;
}
