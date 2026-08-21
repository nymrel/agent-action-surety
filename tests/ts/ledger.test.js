/**
 * Unit Tests: Cryptographic Execution Ledger (Node.js)
 * Zero external dependencies.
 */

import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import { ExecutionLedger } from '../../dist/ledger.js';

describe('ExecutionLedger Suite', () => {
  const secretKey = 'nymrel_hmac_secret_testing_key_2026';

  it('records actions and produces valid SHA-256 hash receipt', () => {
    const ledger = new ExecutionLedger({ hmacSecret: secretKey });
    const action = {
      actionType: 'exec',
      command: 'git status',
      estimatedCostUsd: 0.001,
    };
    const evaluation = {
      decision: 'ALLOW',
      allowed: true,
      reasons: ['Safe command'],
      violations: [],
      capabilitiesRequired: ['exec:read_only'],
      timestamp: 1770000000000,
    };

    const receipt = ledger.recordAction(action, evaluation);

    assert.ok(receipt.receiptId.startsWith('rcpt_'));
    assert.strictEqual(receipt.prevReceiptHash, ExecutionLedger.GENESIS_PREV_HASH);
    assert.strictEqual(receipt.receiptHash.length, 64);
    assert.ok(receipt.signature, 'Signature should be present');

    const isValid = ExecutionLedger.verifyReceipt(receipt, secretKey);
    assert.strictEqual(isValid, true, 'Receipt should verify authentic');
  });

  it('detects tampering in receipt fields', () => {
    const ledger = new ExecutionLedger({ hmacSecret: secretKey });
    const action = { actionType: 'fs_read', targetPath: './safe.txt' };
    const evaluation = {
      decision: 'ALLOW',
      allowed: true,
      reasons: ['Allowed'],
      violations: [],
      capabilitiesRequired: ['fs:read'],
      timestamp: 1770000000000,
    };

    const receipt = ledger.recordAction(action, evaluation);

    const tamperedReceipt = { ...receipt, decision: 'DENY' };
    const isValid = ExecutionLedger.verifyReceipt(tamperedReceipt, secretKey);
    assert.strictEqual(isValid, false, 'Tampered receipt must fail verification');
  });

  it('maintains a continuous cryptographic hash chain', () => {
    const ledger = new ExecutionLedger({ hmacSecret: secretKey });

    const r1 = ledger.recordAction(
      { actionType: 'exec', command: 'echo 1' },
      { decision: 'ALLOW', allowed: true, reasons: [], violations: [], capabilitiesRequired: ['exec:read_only'], timestamp: 1000 }
    );
    const r2 = ledger.recordAction(
      { actionType: 'exec', command: 'echo 2' },
      { decision: 'ALLOW', allowed: true, reasons: [], violations: [], capabilitiesRequired: ['exec:read_only'], timestamp: 2000 }
    );
    const r3 = ledger.recordAction(
      { actionType: 'exec', command: 'echo 3' },
      { decision: 'ALLOW', allowed: true, reasons: [], violations: [], capabilitiesRequired: ['exec:read_only'], timestamp: 3000 }
    );

    assert.strictEqual(r1.prevReceiptHash, ExecutionLedger.GENESIS_PREV_HASH);
    assert.strictEqual(r2.prevReceiptHash, r1.receiptHash);
    assert.strictEqual(r3.prevReceiptHash, r2.receiptHash);

    const history = ledger.getHistory();
    const chainVerification = ExecutionLedger.verifyChain(history, secretKey);
    assert.strictEqual(chainVerification.valid, true);

    const tamperedHistory = [...history];
    tamperedHistory[1] = { ...tamperedHistory[1], commandSummary: 'malicious modification' };
    const brokenVerification = ExecutionLedger.verifyChain(tamperedHistory, secretKey);
    assert.strictEqual(brokenVerification.valid, false);
    assert.strictEqual(brokenVerification.brokenIndex, 1);
  });
});
