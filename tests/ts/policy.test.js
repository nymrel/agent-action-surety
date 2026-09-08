/**
 * Unit Tests: Policy Engine & Envelope (Node.js)
 * Zero external dependencies.
 */

import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import { PolicyEngine, wrapExecution } from '../../dist/index.js';

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

  it('requires exec:modify for helper-capable ripgrep and Git commands', async () => {
    const commands = [
      'rg needle README.md',
      'rg --no-config --pre helper needle README.md',
      'rg --no-config --hostname-bin helper needle README.md',
      'rg --no-config -z needle archive.gz',
      'rg --no-config --search-zip=true needle archive.gz',
      'rg -- --no-config README.md',
      'rg -e --no-config README.md',
      'rg -n --no-config needle README.md',
      'echo ok && git status',
      'echo ok|git commit',
      'echo $(git status)',
      'rg --no-config needle README.md && git status',
      'npm --version',
      'python --version',
      'hostname changed-host',
      'git status',
      'git diff --ext-diff',
      'git diff --textconv',
      'Git status',
      '"git" status',
    ];

    for (const command of commands) {
      const engine = new PolicyEngine({
        capabilities: ['exec:read_only', 'git:read'],
      });
      let executorCalled = false;
      const result = await wrapExecution(
        engine,
        { actionType: 'exec', command },
        undefined,
        () => {
          executorCalled = true;
          return 'unexpected';
        },
      );

      assert.strictEqual(result.evaluation.allowed, false, command);
      assert.ok(result.evaluation.capabilitiesRequired.includes('exec:modify'), command);
      assert.strictEqual(executorCalled, false, command);
    }
  });

  it('admits only the bounded no-config ripgrep profile as read-only', () => {
    const engine = new PolicyEngine({ capabilities: ['exec:read_only'] });
    const safe = engine.evaluate({
      actionType: 'exec',
      command: 'rg --no-config needle README.md',
    });

    assert.strictEqual(safe.allowed, true);
    assert.deepStrictEqual(safe.capabilitiesRequired, ['exec:read_only']);

    const hostname = engine.evaluate({ actionType: 'exec', command: 'hostname' });
    assert.strictEqual(hostname.allowed, true);
    assert.deepStrictEqual(hostname.capabilitiesRequired, ['exec:read_only']);
  });

  it('requires exec:modify for explicit Git action envelopes', () => {
    const engine = new PolicyEngine({ capabilities: ['git:read'] });
    const result = engine.evaluate({ actionType: 'git', command: 'git status' });

    assert.strictEqual(result.allowed, false);
    assert.deepStrictEqual(result.capabilitiesRequired, ['exec:modify', 'git:read']);
  });

  it('recognizes quoted and case-varied direct Git capabilities', () => {
    const engine = new PolicyEngine({ capabilities: [] });

    assert.deepStrictEqual(
      engine.inferRequiredCapabilities({ actionType: 'exec', command: '"Git" push --force-with-lease' }),
      ['exec:privileged', 'git:force_push'],
    );
    assert.deepStrictEqual(
      engine.inferRequiredCapabilities({ actionType: 'exec', command: 'C:\\Tools\\Git.exe commit -m message' }),
      ['exec:modify', 'git:commit'],
    );
    assert.deepStrictEqual(
      engine.inferRequiredCapabilities({ actionType: 'exec', command: 'C:\\Tools\\Git.exe push -fv origin main' }),
      ['exec:privileged', 'git:force_push'],
    );
    assert.deepStrictEqual(
      engine.inferRequiredCapabilities({ actionType: 'exec', command: 'git push origin +main' }),
      ['exec:privileged', 'git:force_push'],
    );
    for (const command of ['git push -vd origin branch', 'git push -dv origin branch']) {
      assert.deepStrictEqual(
        engine.inferRequiredCapabilities({ actionType: 'exec', command }),
        ['exec:privileged', 'git:force_push'],
      );
    }
    assert.deepStrictEqual(
      engine.inferRequiredCapabilities({ actionType: 'exec', command: 'git reset --hard HEAD~1' }),
      ['exec:privileged', 'git:commit'],
    );
    assert.deepStrictEqual(
      engine.inferRequiredCapabilities({ actionType: 'exec', command: '"Git" reset --hard HEAD~1' }),
      ['exec:privileged', 'git:commit'],
    );
    assert.deepStrictEqual(
      engine.inferRequiredCapabilities({ actionType: 'exec', command: 'C:\\Tools\\Git.exe reset --hard HEAD~1' }),
      ['exec:privileged', 'git:commit'],
    );
    assert.deepStrictEqual(
      engine.inferRequiredCapabilities({ actionType: 'exec', command: 'git -C repo reset --hard HEAD~1' }),
      ['exec:privileged', 'git:commit'],
    );
    assert.deepStrictEqual(
      engine.inferRequiredCapabilities({ actionType: 'git', command: 'reset --hard HEAD~1' }),
      ['exec:privileged', 'git:commit'],
    );
    assert.deepStrictEqual(
      engine.inferRequiredCapabilities({ actionType: 'exec', command: 'git branch --delete main' }),
      ['exec:privileged', 'git:commit'],
    );
    assert.deepStrictEqual(
      engine.inferRequiredCapabilities({ actionType: 'exec', command: 'git config status changed' }),
      ['exec:modify', 'git:commit'],
    );
    assert.deepStrictEqual(
      engine.inferRequiredCapabilities({ actionType: 'exec', command: 'git --no-pager status' }),
      ['exec:modify', 'git:read'],
    );
    assert.deepStrictEqual(
      engine.inferRequiredCapabilities({ actionType: 'exec', command: 'git -c color.ui=false status' }),
      ['exec:modify', 'git:read'],
    );
    assert.deepStrictEqual(
      engine.inferRequiredCapabilities({ actionType: 'exec', command: 'git unknown-subcommand' }),
      ['exec:modify', 'git:commit'],
    );
  });
});
