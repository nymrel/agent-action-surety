/**
 * Unit Tests: Filesystem Path Sandbox (Node.js)
 * Zero external dependencies.
 */

import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import * as path from 'node:path';
import * as fs from 'node:fs';
import * as os from 'node:os';
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

  describe('Intra-call Canonicalization Deduplication', () => {
    class CountingSandbox extends SuretySandbox {
      canonicalizeCalls = 0;
      canonicalizePath(targetPath) {
        // Defensive init: the base constructor invokes this override before
        // the field initializer above has run.
        this.canonicalizeCalls = (this.canonicalizeCalls || 0) + 1;
        return super.canonicalizePath(targetPath);
      }
    }

    it('canonicalizes exactly once for an allowed validatePath call', () => {
      const sb = new CountingSandbox({ workspaceRoots: [rootDir], readOnlyRoots: [readOnlyDir] });
      sb.canonicalizeCalls = 0; // exclude constructor root canonicalization
      const res = sb.validatePath(path.join(rootDir, 'src', 'app.ts'), false);
      assert.strictEqual(res.allowed, true);
      assert.strictEqual(sb.canonicalizeCalls, 1);
    });

    it('canonicalizes exactly once for a traversal-denied validatePath call', () => {
      const sb = new CountingSandbox({ workspaceRoots: [rootDir] });
      sb.canonicalizeCalls = 0;
      // Raw '..' segments preserved (path.join would collapse them).
      const res = sb.validatePath(`${rootDir}${path.sep}..${path.sep}..${path.sep}etc${path.sep}passwd`, false);
      assert.strictEqual(res.allowed, false);
      assert.ok(res.reason?.includes('Path traversal detected'));
      assert.strictEqual(sb.canonicalizeCalls, 1);
    });

    it('blocks double-encoded traversal with one filesystem canonicalization', () => {
      const sb = new CountingSandbox({ workspaceRoots: [rootDir] });
      sb.canonicalizeCalls = 0;
      const res = sb.validatePath(`${rootDir}${path.sep}%252e%252e${path.sep}outside.txt`, false);
      assert.strictEqual(res.allowed, false);
      assert.strictEqual(sb.canonicalizeCalls, 1);
    });

    it('preserves subclass security-hook overrides', () => {
      class DenyAllSandbox extends SuretySandbox {
        isSensitivePath() { return true; }
      }
      const sb = new DenyAllSandbox({ workspaceRoots: [rootDir] });
      const res = sb.validatePath(path.join(rootDir, 'otherwise-safe.txt'), false);
      assert.strictEqual(res.allowed, false);
      assert.ok(res.reason?.includes('sensitive path blocked'));
    });

    it('preserves custom deny patterns over the once-decoded path', () => {
      const sb = new SuretySandbox({
        workspaceRoots: [rootDir],
        deniedPatterns: ['blocked%2fname$'],
      });
      const res = sb.validatePath(path.join(rootDir, 'blocked%252fname'), false);
      assert.strictEqual(res.allowed, false);
      assert.ok(res.reason?.includes('sensitive path blocked'));
    });

    it('fails closed on otherwise-safe multi-layer encoded paths', () => {
      const sb = new SuretySandbox({ workspaceRoots: [rootDir] });
      const res = sb.validatePath(path.join(rootDir, 'vault%252fchild'), false);
      assert.strictEqual(res.allowed, false);
      assert.ok(res.reason?.includes('Multi-layer URI encoding'));
    });

    it('performs fresh canonicalization on every call (no cross-call caching)', () => {
      const sb = new CountingSandbox({ workspaceRoots: [rootDir] });
      sb.canonicalizeCalls = 0;
      const target = path.join(rootDir, 'a.ts');
      assert.strictEqual(sb.validatePath(target, false).allowed, true);
      assert.strictEqual(sb.validatePath(target, false).allowed, true);
      assert.strictEqual(sb.canonicalizeCalls, 2);
    });

    it('reduces canonicalization work versus the public-helper composition', () => {
      // Reproduces the pre-dedup call graph using only the public helpers:
      // sensitive check on raw + canonical, then containment against each
      // root (each isPathContained re-canonicalizes both arguments).
      const naiveSb = new CountingSandbox({ workspaceRoots: [rootDir], readOnlyRoots: [readOnlyDir] });
      naiveSb.canonicalizeCalls = 0;
      const target = path.join(rootDir, 'src', 'app.ts');
      const canonical = naiveSb.canonicalizePath(target);
      naiveSb.isSensitivePath(target);
      naiveSb.isSensitivePath(canonical);
      for (const root of [rootDir]) naiveSb.isPathContained(canonical, root);
      for (const roRoot of [readOnlyDir]) naiveSb.isPathContained(canonical, roRoot);

      const fastSb = new CountingSandbox({ workspaceRoots: [rootDir], readOnlyRoots: [readOnlyDir] });
      fastSb.canonicalizeCalls = 0;
      fastSb.validatePath(target, false);

      assert.strictEqual(fastSb.canonicalizeCalls, 1);
      assert.ok(
        fastSb.canonicalizeCalls < naiveSb.canonicalizeCalls,
        `expected ${fastSb.canonicalizeCalls} < ${naiveSb.canonicalizeCalls}`
      );
    });

    it('preserves validation outcomes across allowed, denied, traversal, and read-only cases', () => {
      const sb = new CountingSandbox({ workspaceRoots: [rootDir], readOnlyRoots: [readOnlyDir] });
      sb.canonicalizeCalls = 0;

      const allowed = sb.validatePath(path.join(rootDir, 'src', 'app.ts'), false);
      assert.deepStrictEqual(
        { allowed: allowed.allowed, isReadOnly: allowed.isReadOnly },
        { allowed: true, isReadOnly: false }
      );

      const deniedSensitive = sb.validatePath(path.join(rootDir, '.env'), false);
      assert.strictEqual(deniedSensitive.allowed, false);
      assert.ok(deniedSensitive.reason?.includes('sensitive path blocked'));

      const deniedTraversal = sb.validatePath(
        `${rootDir}${path.sep}..${path.sep}outside.txt`,
        false
      );
      assert.strictEqual(deniedTraversal.allowed, false);
      assert.ok(deniedTraversal.reason?.includes('Path traversal detected'));

      const roRead = sb.validatePath(path.join(readOnlyDir, 'lib.js'), false);
      assert.deepStrictEqual(
        { allowed: roRead.allowed, isReadOnly: roRead.isReadOnly },
        { allowed: true, isReadOnly: true }
      );

      const roWrite = sb.validatePath(path.join(readOnlyDir, 'new.js'), true);
      assert.strictEqual(roWrite.allowed, false);
      assert.ok(roWrite.reason?.includes('read-only root'));
    });

    it('blocks symlinked sensitive paths via canonical resolution', () => {
      const wsRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'surety-ws-'));
      const outsideRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'surety-out-'));
      try {
        const secretDir = path.join(outsideRoot, '.ssh');
        fs.mkdirSync(secretDir);
        fs.writeFileSync(path.join(secretDir, 'id_rsa'), 'secret');
        const link = path.join(wsRoot, 'sshlink');
        // 'junction' needs no elevation on Windows; treated as a dir symlink elsewhere.
        fs.symlinkSync(secretDir, link, 'junction');

        const sb = new SuretySandbox({ workspaceRoots: [wsRoot] });
        const res = sb.validatePath(path.join(link, 'id_rsa'), false);
        assert.strictEqual(res.allowed, false);
        assert.ok(res.reason?.includes('sensitive path blocked'));
      } finally {
        fs.rmSync(wsRoot, { recursive: true, force: true });
        fs.rmSync(outsideRoot, { recursive: true, force: true });
      }
    });
  });
});
