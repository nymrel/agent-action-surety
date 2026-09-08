/**
 * Unit Tests: CLI Engine (Node.js)
 * Zero external dependencies.
 */

import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runCli } from '../../dist/cli.js';
import {
  parseCommandArgv,
  PolicyEngine,
  wrapExecution,
} from '../../dist/index.js';

describe('CLI Engine Suite', () => {
  it('returns code 0 for safe check command', async () => {
    const code = await runCli(['check', '--cmd', 'echo "Hello Surety"']);
    assert.strictEqual(code, 0);
  });

  it('returns code 1 for dangerous check command', async () => {
    const code = await runCli(['check', '--cmd', 'rm -rf /']);
    assert.strictEqual(code, 1);
  });

  it('returns code 1 when check receives an unparseable command', async () => {
    const code = await runCli(['check', '--cmd', 'tool "unterminated']);
    assert.strictEqual(code, 1);
  });

  it('ships an executable compiled CLI instead of the legacy JavaScript wrapper', () => {
    const manifest = JSON.parse(
      fs.readFileSync(path.resolve('package.json'), 'utf8')
    );
    assert.strictEqual(manifest.bin['agent-surety'], './dist/cli.js');
    assert.strictEqual(manifest.files.includes('bin'), false);

    const result = spawnSync(
      process.execPath,
      [path.resolve('dist/cli.js'), '--help'],
      { encoding: 'utf8' }
    );
    assert.strictEqual(result.status, 0, result.stderr);
    assert.match(result.stdout, /AGENT ACTION SURETY/);
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
    };

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
    fakeReceipt.receiptHash = ExecutionLedger.sha256(ExecutionLedger.canonicalizeData(payload));

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

  it('parses the portable argv contract without changing Windows paths', () => {
    assert.deepStrictEqual(
      parseCommandArgv(`tool "two words" 'three words' C:\\path ""`),
      ['tool', 'two words', 'three words', 'C:\\path', '']
    );
    assert.deepStrictEqual(
      parseCommandArgv(`tool "quote: \\" and slash: \\\\"`),
      ['tool', 'quote: " and slash: \\']
    );
  });

  it('rejects malformed, empty, oversized, and controlled command strings', () => {
    assert.throws(() => parseCommandArgv('   \t\r\n'), /include an executable/i);
    assert.throws(() => parseCommandArgv('""'), /must not be empty/i);
    assert.throws(() => parseCommandArgv('tool "unterminated'), /unterminated/i);
    assert.throws(() => parseCommandArgv('tool\u0000arg'), /control character/i);
    assert.throws(() => parseCommandArgv(`tool ${'x'.repeat(32_768)}`), /safety limit/i);
  });

  it('does not interpret a chained command through a shell', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'surety-no-shell-'));
    const marker = path.join(tempDir, 'must-not-exist.txt');
    const firstScript = `process.stdout.write('surety-ok')`;
    const secondScript = `require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'owned')`;
    const command = [
      JSON.stringify(process.execPath),
      '-e',
      JSON.stringify(firstScript),
      '&&',
      JSON.stringify(process.execPath),
      '-e',
      JSON.stringify(secondScript),
    ].join(' ');
    const engine = new PolicyEngine({
      capabilities: ['exec:modify'],
      allowedPaths: [tempDir],
    });

    try {
      const result = await wrapExecution(engine, {
        actionType: 'exec',
        command,
        workingDir: tempDir,
      });

      assert.strictEqual(result.evaluation.allowed, true);
      assert.strictEqual(result.success, true);
      assert.strictEqual(result.exitCode, 0);
      assert.strictEqual(result.output, 'surety-ok');
      assert.strictEqual(fs.existsSync(marker), false);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('denies a chain after a read-only prefix before execution', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'surety-read-only-'));
    const marker = path.join(tempDir, 'must-not-exist.txt');
    const writer = `require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'owned')`;
    const command = [
      'node -v',
      '&&',
      JSON.stringify(process.execPath),
      '-e',
      JSON.stringify(writer),
    ].join(' ');
    const engine = new PolicyEngine({
      capabilities: ['exec:read_only'],
      allowedPaths: [tempDir],
    });

    try {
      const result = await wrapExecution(engine, {
        actionType: 'exec',
        command,
        workingDir: tempDir,
      });

      assert.strictEqual(result.evaluation.allowed, false);
      assert.deepStrictEqual(result.evaluation.capabilitiesRequired, ['exec:modify']);
      assert.strictEqual(result.success, false);
      assert.strictEqual(fs.existsSync(marker), false);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('records a DENY before policy or custom execution on parse failure', async () => {
    const engine = new PolicyEngine({ capabilities: ['exec:modify'] });
    let executorCalled = false;
    const result = await wrapExecution(
      engine,
      { actionType: 'exec', command: 'tool "unterminated' },
      undefined,
      () => {
        executorCalled = true;
        return 'unexpected';
      }
    );

    assert.strictEqual(executorCalled, false);
    assert.strictEqual(result.success, false);
    assert.strictEqual(result.evaluation.allowed, false);
    assert.strictEqual(result.evaluation.decision, 'DENY');
    assert.strictEqual(result.receipt.decision, 'DENY');
    assert.match(result.error || '', /denied by surety command parser/i);
  });
});
