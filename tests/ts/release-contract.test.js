import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { describe, test } from 'node:test';

const verifier = path.resolve('scripts/verify-release.mjs');

function fixture(overrides = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'surety-release-'));
  const npmPackage = {
    name: '@nymrel/agent-surety',
    version: '1.0.0',
    repository: { type: 'git', url: 'https://github.com/nymrel/agent-action-surety.git' },
    packageManager: 'npm@11.19.1',
    engines: { node: '>=22.22.2 <27' },
    devEngines: {
      runtime: { name: 'node', version: '>=22.22.2 <27', onFail: 'error' },
      packageManager: { name: 'npm', version: '11.19.1', onFail: 'error' },
    },
    sideEffects: false,
    exports: { '.': { types: './dist/index.d.ts', import: './dist/index.js', default: './dist/index.js' } },
    files: ['dist', 'LICENSE', 'README.md'],
    ...overrides.npm,
  };
  const python = {
    name: 'agent-action-surety',
    version: '1.0.0',
    runtime: '>=3.11,<3.15',
    buildBackend: 'setuptools.build_meta',
    buildRequirements: ['setuptools==84.0.0'],
    dependencies: [],
    ...overrides.python,
  };
  fs.writeFileSync(path.join(root, 'package.json'), `${JSON.stringify(npmPackage, null, 2)}\n`);
  fs.writeFileSync(path.join(root, 'pyproject.toml'), [
    '[build-system]',
    `requires = ${JSON.stringify(python.buildRequirements)}`,
    `build-backend = "${python.buildBackend}"`,
    '',
    '[project]',
    `name = "${python.name}"`,
    `version = "${python.version}"`,
    `requires-python = "${python.runtime}"`,
    `dependencies = ${JSON.stringify(python.dependencies)}`,
    'classifiers = [',
    '  "Programming Language :: Python :: 3.11",',
    '  "Programming Language :: Python :: 3.14",',
    ']',
    '',
  ].join('\n'));
  fs.writeFileSync(path.join(root, 'setup.py'), '"""Compatibility shim; all package metadata lives in pyproject.toml."""\n\nfrom setuptools import setup\n\n\nsetup()\n');
  return root;
}

function verify(root, tag = 'v1.0.0') {
  return spawnSync(process.execPath, [verifier, '--root', root, '--tag', tag], { encoding: 'utf8' });
}

function withFixture(overrides, callback) {
  const root = fixture(overrides);
  try { callback(root); } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

describe('release contract', () => {
  test('accepts exact dual-package metadata', () => withFixture({}, (root) => {
    const result = verify(root);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).ok, true);
  }));

  test('rejects version and unstable-tag drift', () => withFixture({ python: { version: '1.0.1' } }, (root) => {
    assert.match(verify(root).stderr, /version parity/);
    assert.match(verify(root, 'v1.0.0-beta.1').stderr, /stable vMAJOR/);
  }));

  test('rejects EOL Node and package-manager drift', () => withFixture({ npm: { engines: { node: '>=18' } } }, (root) => {
    assert.match(verify(root).stderr, /Node engine/);
  }));

  test('rejects EOL Python and mutable build inputs', () => withFixture({ python: { runtime: '>=3.9', buildRequirements: ['setuptools>=77'] } }, (root) => {
    assert.match(verify(root).stderr, /Python runtime requirement/);
  }));

  test('rejects distribution-boundary bypasses', () => withFixture({ npm: { exports: { '.': { types: './src/index.ts', import: './src/index.ts', default: './src/index.ts' } } } }, (root) => {
    assert.match(verify(root).stderr, /root type export/);
  }));

  test('rejects runtime dependencies in either ecosystem', () => withFixture({ npm: { dependencies: { leftpad: '1.0.0' } } }, (root) => {
    assert.match(verify(root).stderr, /runtime dependency count/);
  }));

  test('rejects duplicated legacy setup metadata', () => withFixture({}, (root) => {
    fs.writeFileSync(path.join(root, 'setup.py'), 'from setuptools import setup\nsetup(name="stale")\n');
    assert.match(verify(root).stderr, /compatibility shim/);
  }));
});
