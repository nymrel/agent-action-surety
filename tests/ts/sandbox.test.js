/**
 * Unit Tests: Filesystem Path Sandbox (Node.js)
 * Zero external dependencies.
 */

import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import * as path from 'node:path';
import { SuretySandbox } from '../../dist/sandbox.js';

describe('SuretySandbox Suite', () => {
  const rootDir = path.resolve('./sandbox_test_root');
  const readOnlyDir = path.join(rootDir, 'vendor');

  const sandbox = new SuretySandbox({
    workspaceRoots: [rootDir],
    readOnlyRoots: [readOnlyDir],
  });

  describe('Workspace Boundary & Path Traversal', () => {
    it('allows paths strictly inside workspace root', () => {
      const target = path.join(rootDir, 'src', 'app.ts');
      const res = sandbox.validatePath(target, false);
      assert.strictEqual(res.allowed, true);
    });

    it('blocks directory traversal targeting parent directories (../../etc/passwd)', () => {
      const target = path.join(rootDir, '..', '..', 'etc', 'passwd');
      const res = sandbox.validatePath(target, false);
      assert.strictEqual(res.allowed, false);
      assert.ok(
        res.reason?.includes('Path traversal detected') ||
        res.reason?.includes('outside allowed workspace roots') ||
        res.reason?.includes('sensitive path blocked')
      );
    });

    it('blocks Windows absolute paths outside workspace root', () => {
      const target = 'C:\\Windows\\System32\\calc.exe';
      const res = sandbox.validatePath(target, false);
      assert.strictEqual(res.allowed, false);
    });
  });

  describe('Sensitive Credential Protection', () => {
    it('blocks access to .env files inside workspace', () => {
      const target = path.join(rootDir, '.env');
      const res = sandbox.validatePath(target, false);
      assert.strictEqual(res.allowed, false);
      assert.ok(res.reason?.includes('sensitive path blocked'));
    });

    it('blocks access to .git/config', () => {
      const target = path.join(rootDir, '.git', 'config');
      const res = sandbox.validatePath(target, false);
      assert.strictEqual(res.allowed, false);
    });

    it('blocks access to SSH private keys', () => {
      const target = path.join(rootDir, '.ssh', 'id_rsa');
      const res = sandbox.validatePath(target, false);
      assert.strictEqual(res.allowed, false);
    });
  });

  describe('Read-Only Root Enforcement', () => {
    it('allows reading from read-only directory', () => {
      const target = path.join(readOnlyDir, 'lib.js');
      const res = sandbox.validatePath(target, false);
      assert.strictEqual(res.allowed, true);
      assert.strictEqual(res.isReadOnly, true);
    });

    it('rejects write operations in read-only directory', () => {
      const target = path.join(readOnlyDir, 'malicious.js');
      const res = sandbox.validatePath(target, true);
      assert.strictEqual(res.allowed, false);
      assert.ok(res.reason?.includes('read-only root'));
    });
  });
});
