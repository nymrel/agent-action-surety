/**
 * Unit Tests: Policy Engine & Envelope (Node.js)
 * Zero external dependencies.
 */

import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import { PolicyEngine } from '../../dist/policy.js';

describe('PolicyEngine Suite', () => {
  it('enforces deny-by-default capability gates', () => {
    const engine = new PolicyEngine({
      capabilities: ['fs:read'], // Only fs:read granted
      allowedPaths: [process.cwd()],
    });

    // fs_read should be allowed
    const readEval = engine.evaluate({
      actionType: 'fs_read',
      targetPath: './src/index.ts',
    });
    assert.strictEqual(readEval.allowed, true);
    assert.strictEqual(readEval.decision, 'ALLOW');

    // fs_write should be denied (missing capability)
    const writeEval = engine.evaluate({
      actionType: 'fs_write',
      targetPath: './src/index.ts',
    });
    assert.strictEqual(writeEval.allowed, false);
    assert.strictEqual(writeEval.decision, 'DENY');
    assert.ok(writeEval.reasons[0].includes('Missing required capabilities'));
  });

  it('supports wildcard capabilities (fs:* grants all fs operations)', () => {
    const engine = new PolicyEngine({
      capabilities: ['fs:*'],
      allowedPaths: [process.cwd()],
    });

    const writeEval = engine.evaluate({
      actionType: 'fs_write',
      targetPath: './src/new_file.txt',
    });
    assert.strictEqual(writeEval.allowed, true);
  });

  it('enforces spend budget caps', () => {
    const engine = new PolicyEngine({
      capabilities: ['exec:read_only'],
      maxSpendUsd: 1.0, // $1.00 budget
    });

    // Action 1: $0.60
    const eval1 = engine.evaluate({
      actionType: 'exec',
      command: 'echo first',
      estimatedCostUsd: 0.60,
    });
    assert.strictEqual(eval1.allowed, true);
    assert.strictEqual(engine.getAccumulatedSpendUsd(), 0.60);

    // Action 2: $0.50 (Total would be $1.10 > $1.00)
    const eval2 = engine.evaluate({
      actionType: 'exec',
      command: 'echo second',
      estimatedCostUsd: 0.50,
    });
    assert.strictEqual(eval2.allowed, false);
    assert.ok(eval2.reasons[0].includes('Spend budget exceeded'));
  });

  it('enforces rate limits per minute', () => {
    const engine = new PolicyEngine({
      capabilities: ['exec:read_only'],
      rateLimitPerMinute: 3,
    });

    const now = Date.now();
    assert.strictEqual(engine.evaluate({ actionType: 'exec', command: 'echo 1', timestamp: now }).allowed, true);
    assert.strictEqual(engine.evaluate({ actionType: 'exec', command: 'echo 2', timestamp: now }).allowed, true);
    assert.strictEqual(engine.evaluate({ actionType: 'exec', command: 'echo 3', timestamp: now }).allowed, true);

    // 4th action should hit rate limit
    const eval4 = engine.evaluate({ actionType: 'exec', command: 'echo 4', timestamp: now });
    assert.strictEqual(eval4.allowed, false);
    assert.ok(eval4.reasons[0].includes('Rate limit exceeded'));
  });
});
