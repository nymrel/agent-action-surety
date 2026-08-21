/**
 * Unit Tests: CLI Engine (Node.js)
 * Zero external dependencies.
 */

import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { runCli } from '../../dist/cli.js';

describe('CLI Engine Suite', () => {
  it('returns code 0 for safe check command', async () => {
    const code = await runCli(['check', '--cmd', 'echo "Hello Surety"']);
    assert.strictEqual(code, 0);
  });

  it('returns code 1 for dangerous check command', async () => {
    const code = await runCli(['check', '--cmd', 'rm -rf /']);
    assert.strictEqual(code, 1);
  });

  it('validates paths within sandbox via CLI', async () => {
    const code = await runCli(['path', '--target', './src/index.ts']);
    assert.strictEqual(code, 0);
  });

  it('blocks sensitive path access via CLI', async () => {
    const code = await runCli(['path', '--target', './.env']);
    assert.strictEqual(code, 1);
  });

  it('verifies receipt file via CLI', async () => {
    const tempReceiptPath = path.resolve('./temp_receipt_test.json');
    const fakeReceipt = {
      receiptId: 'rcpt_1234567890_test',
      sessionId: 'session_test_cli',
      actionId: 'act_123_test',
      actionType: 'exec',
      decision: 'ALLOW',
      violationsCount: 0,
      prevReceiptHash: '0000000000000000000000000000000000000000000000000000000000000000',
      commandSummary: 'echo test',
      timestamp: 1770000000000,
      metadata: {},
      // Compute actual hash for this payload
    };

    // Use ExecutionLedger helper to calculate valid hash
    const { ExecutionLedger } = await import('../../dist/ledger.js');
    const payload = {
      actionId: fakeReceipt.actionId,
      actionType: fakeReceipt.actionType,
      commandSummary: fakeReceipt.commandSummary,
      decision: fakeReceipt.decision,
      metadata: fakeReceipt.metadata,
      prevReceiptHash: fakeReceipt.prevReceiptHash,
      receiptId: fakeReceipt.receiptId,
      sessionId: fakeReceipt.sessionId,
      targetPath: undefined,
      timestamp: fakeReceipt.timestamp,
      violationsCount: 0,
    };
    (fakeReceipt as any).receiptHash = ExecutionLedger.sha256(ExecutionLedger.canonicalizeData(payload));

    fs.writeFileSync(tempReceiptPath, JSON.stringify(fakeReceipt, null, 2), 'utf-8');

    try {
      const code = await runCli(['verify-receipt', '--file', tempReceiptPath]);
      assert.strictEqual(code, 0);
    } finally {
      if (fs.existsSync(tempReceiptPath)) {
        fs.unlinkSync(tempReceiptPath);
      }
    }
  });
});
