import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';

const EXPECTED = Object.freeze({
  npmName: '@nymrel/agent-surety',
  pythonName: 'agent-action-surety',
  repository: 'https://github.com/nymrel/agent-action-surety.git',
  packageManager: 'npm@11.19.1',
  nodeRange: '>=22.22.2 <27',
  pythonRange: '>=3.11,<3.15',
  pythonBuildBackend: 'setuptools.build_meta',
  pythonBuildRequirements: ['setuptools==84.0.0'],
  npmFiles: ['dist', 'LICENSE', 'README.md'],
  setupShim: '"""Compatibility shim; all package metadata lives in pyproject.toml."""\n\nfrom setuptools import setup\n\n\nsetup()\n',
});

function fail(message) {
  process.stderr.write(`release verification failed: ${message}\n`);
  process.exit(1);
}

function option(name, fallback) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : fallback;
}

function readText(root, relative) {
  return fs.readFileSync(path.join(root, relative), 'utf8').replace(/\r\n/g, '\n');
}

function tomlSection(toml, name) {
  const lines = toml.split('\n');
  const start = lines.findIndex((line) => line.trim() === `[${name}]`);
  if (start < 0) fail(`pyproject.toml is missing [${name}]`);
  let end = lines.length;
  for (let index = start + 1; index < lines.length; index += 1) {
    if (/^\s*\[[^\]]+\]\s*$/.test(lines[index])) {
      end = index;
      break;
    }
  }
  return lines.slice(start + 1, end).join('\n');
}

function tomlString(section, key) {
  const escaped = key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const match = section.match(new RegExp(`^${escaped}\\s*=\\s*"([^"]+)"\\s*$`, 'm'));
  if (!match) fail(`pyproject.toml is missing ${key}`);
  return match[1];
}

function tomlStringArray(section, key) {
  const escaped = key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const match = section.match(new RegExp(`^${escaped}\\s*=\\s*(\\[[^\\n]*\\])\\s*$`, 'm'));
  if (!match) fail(`pyproject.toml is missing ${key}`);
  try {
    const values = JSON.parse(match[1]);
    if (!Array.isArray(values) || values.some((value) => typeof value !== 'string')) throw new Error('not strings');
    return values;
  } catch {
    fail(`pyproject.toml ${key} must be a one-line string array`);
  }
}

function expectEqual(actual, expected, label) {
  if (actual !== expected) fail(`${label} must be ${JSON.stringify(expected)}, found ${JSON.stringify(actual)}`);
}

function expectArrayEqual(actual, expected, label) {
  if (actual.length !== expected.length || actual.some((value, index) => value !== expected[index])) {
    fail(`${label} must be ${JSON.stringify(expected)}, found ${JSON.stringify(actual)}`);
  }
}

function main() {
  const root = path.resolve(option('--root', process.cwd()));
  const npmPackage = JSON.parse(readText(root, 'package.json'));
  const requestedTag = option('--tag', process.env.GITHUB_REF_TYPE === 'tag' ? process.env.GITHUB_REF_NAME : undefined);
  const tag = requestedTag ?? `v${npmPackage.version}`;
  if (!/^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(tag)) {
    fail(`tag ${JSON.stringify(tag)} is not a stable vMAJOR.MINOR.PATCH release`);
  }

  const pyproject = readText(root, 'pyproject.toml');
  const build = tomlSection(pyproject, 'build-system');
  const project = tomlSection(pyproject, 'project');
  const pythonName = tomlString(project, 'name');
  const pythonVersion = tomlString(project, 'version');
  const pythonRange = tomlString(project, 'requires-python');

  expectEqual(npmPackage.name, EXPECTED.npmName, 'npm package name');
  expectEqual(pythonName, EXPECTED.pythonName, 'Python package name');
  expectEqual(npmPackage.version, pythonVersion, 'npm/Python version parity');
  expectEqual(npmPackage.version, tag.slice(1), 'tag/package version parity');
  expectEqual(npmPackage.repository?.url, EXPECTED.repository, 'npm repository URL');
  expectEqual(npmPackage.packageManager, EXPECTED.packageManager, 'npm package manager');
  expectEqual(npmPackage.engines?.node, EXPECTED.nodeRange, 'npm Node engine');
  expectEqual(npmPackage.devEngines?.runtime?.name, 'node', 'development runtime name');
  expectEqual(npmPackage.devEngines?.runtime?.version, EXPECTED.nodeRange, 'development runtime range');
  expectEqual(npmPackage.devEngines?.runtime?.onFail, 'error', 'development runtime failure policy');
  expectEqual(npmPackage.devEngines?.packageManager?.name, 'npm', 'development package-manager name');
  expectEqual(npmPackage.devEngines?.packageManager?.version, '11.19.1', 'development package-manager version');
  expectEqual(npmPackage.devEngines?.packageManager?.onFail, 'error', 'development package-manager failure policy');
  expectEqual(npmPackage.sideEffects, false, 'npm sideEffects contract');
  expectEqual(npmPackage.exports?.['.']?.types, './dist/index.d.ts', 'npm root type export');
  expectEqual(npmPackage.exports?.['.']?.import, './dist/index.js', 'npm root ESM export');
  expectEqual(npmPackage.exports?.['.']?.default, './dist/index.js', 'npm root default export');
  expectArrayEqual(npmPackage.files ?? [], EXPECTED.npmFiles, 'npm files boundary');
  expectEqual(Object.keys(npmPackage.dependencies ?? {}).length, 0, 'npm runtime dependency count');

  expectEqual(pythonRange, EXPECTED.pythonRange, 'Python runtime requirement');
  expectEqual(tomlString(build, 'build-backend'), EXPECTED.pythonBuildBackend, 'Python build backend');
  expectArrayEqual(tomlStringArray(build, 'requires'), EXPECTED.pythonBuildRequirements, 'Python build requirements');
  expectArrayEqual(tomlStringArray(project, 'dependencies'), [], 'Python runtime dependencies');
  expectEqual(readText(root, 'setup.py'), EXPECTED.setupShim, 'setup.py compatibility shim');
  if (/Programming Language :: Python :: 3\.(?:9|10)"/.test(pyproject)) fail('EOL Python classifiers remain');

  process.stdout.write(`${JSON.stringify({
    ok: true,
    tag,
    version: npmPackage.version,
    npm: npmPackage.name,
    python: pythonName,
    node: EXPECTED.nodeRange,
    pythonRuntime: pythonRange,
    repository: EXPECTED.repository.replace(/\.git$/, ''),
  })}\n`);
}

main();
