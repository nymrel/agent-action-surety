import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';

const root = path.resolve('.');
const read = (relative) => fs.readFileSync(path.join(root, relative), 'utf8');
const ci = read('.github/workflows/ci.yml');
const codeql = read('.github/workflows/codeql.yml');
const release = read('.github/workflows/publish.yml');
const workflows = `${ci}\n${codeql}\n${release}`;

function actionReferences(document) {
  return [...document.matchAll(/uses:\s+([^@\s]+)@([^\s#]+)/g)].map((match) => ({ action: match[1], reference: match[2] }));
}

test('runtime matrices cover maintained families and exclude EOL lanes', () => {
  for (const version of ["'22'", "'24'", "'26'"]) assert.ok(ci.includes(`node-version: ${version}`));
  for (const version of ["'3.11'", "'3.12'", "'3.13'", "'3.14'"]) assert.ok(ci.includes(`python-version: ${version}`));
  for (const unsupported of ["node-version: '18'", "node-version: '20'", "python-version: '3.9'", "python-version: '3.10'"]) {
    assert.equal(ci.includes(unsupported), false, `CI retains ${unsupported}`);
  }
  assert.equal(/(?:ubuntu|windows)-latest/.test(workflows), false);
});

test('exact npm is active before every repository package command', () => {
  const bootstrap = 'npm install --global npm@12.0.2 --ignore-scripts --no-audit --no-fund';
  assert.equal((workflows.match(/npm install --global npm@12\.0\.2/g) ?? []).length, 4);
  assert.equal((workflows.match(/package-manager-cache:\s*false/g) ?? []).length, 4);
  assert.equal(/^\s*cache:\s*(?:npm|pip)\s*$/m.test(workflows), false);
  for (const document of [ci, release]) {
    assert.ok(document.indexOf(bootstrap) < document.indexOf('npm ci --ignore-scripts --no-audit --no-fund'));
  }
});

test('third-party actions are immutable and checkout credentials never persist', () => {
  const references = actionReferences(workflows);
  for (const { action, reference } of references) assert.match(reference, /^[0-9a-f]{40}$/, `${action} is mutable`);
  const checkoutCount = references.filter(({ action }) => action === 'actions/checkout').length;
  assert.equal((workflows.match(/persist-credentials:\s*false/g) ?? []).length, checkoutCount);
  assert.equal(/continue-on-error|\|\|\s*true|\|\|\s*echo/.test(workflows), false);
});

test('one release bundle is clean-installed, attested, and reused', () => {
  const manifest = release.indexOf('nymrel-surety-consumer');
  const install = release.indexOf('npm install --ignore-scripts --no-audit --no-fund --prefix');
  assert.ok(manifest >= 0 && manifest < install);
  assert.equal((release.match(/actions\/upload-artifact@/g) ?? []).length, 1);
  assert.ok(release.includes('actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8'));
  assert.ok(release.includes('needs: [build, attest-release]'));
  assert.equal(release.includes('NPM_TOKEN'), false);
  assert.equal(release.includes('skip-existing'), false);
});

test('CodeQL and workflow self-audit retain explicit least privilege', () => {
  assert.ok(codeql.includes('security-events: write # Upload CodeQL results'));
  assert.ok(codeql.includes('github/codeql-action/init@cdf488f595d80d6e07e03d4674febd5ab45fa938'));
  assert.ok(ci.includes('zizmorcore/zizmor-action@cc914d7f3750a2d13d75c7f184a1060aa0e9d482'));
  assert.ok(release.includes('attestations: write # Create provenance'));
  assert.ok(release.includes('id-token: write # Exchange the workflow identity'));
});
