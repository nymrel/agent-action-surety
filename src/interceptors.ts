/**
 * Agent Action Surety - Command & SQL Interceptors
 * Deep pattern & token inspection for destructive operations.
 * Zero external dependencies.
 * Copyright (c) 2026 Nymrel / JalenBuilds LLC.
 */

import { InterceptorRule, InterceptorMatch, InterceptorCategory } from './types.js';

export class CommandInterceptor {
  private rules: InterceptorRule[] = [];

  constructor(customRules?: InterceptorRule[]) {
    this.initDefaultRules();
    if (customRules && customRules.length > 0) {
      this.rules.push(...customRules);
    }
  }

  private initDefaultRules(): void {
    // 1. SHELL & FILESYSTEM DESTRUCTION RULES
    this.addRule({
      id: 'SHELL-001',
      name: 'Root or Wildcard Recursive Deletion',
      category: 'SHELL',
      description: 'Matches attempts to recursively delete system root, home, current dir, or wildcards.',
      severity: 'CRITICAL',
      pattern: /(rm\s+-(r|rf|fr|f\s+-r)\s+(\/|~|\$HOME|\*|\.\s|\.\/\*|C:\\|\/boot|\/etc|\/usr|\/var))|(rmdir\s+\/(s|q)\s+(C:\\|\/|\\))|(del\s+\/[fsq\s]+\s*(C:\\|\*|\.\*))/i,
      remediation: 'Scope deletions to an explicit relative directory inside the project sandbox.',
    });

    this.addRule({
      id: 'SHELL-002',
      name: 'Disk Block Destruction or Format',
      category: 'SHELL',
      description: 'Matches raw block device writes or partition formatting (mkfs, dd, format).',
      severity: 'CRITICAL',
      pattern: /(mkfs(\.[a-z0-9]+)?\s+\/dev\/)|(dd\s+if=[^\s]+\s+of=\/dev\/(sd[a-z]|nvme|vd[a-z]|disk|rdisk))|(format\s+[a-zA-Z]:\s*\/[qfsy])/i,
      remediation: 'Avoid raw disk manipulation from autonomous agent sessions.',
    });

    this.addRule({
      id: 'SHELL-003',
      name: 'Fork Bomb Signature',
      category: 'SHELL',
      description: 'Detects bash/sh fork bomb patterns that cause denial of service.',
      severity: 'CRITICAL',
      pattern: /(:(\(\)\s*\{|{\s*:\|:&|\s*:\s*\|\s*:\s*&\s*};\s*:)|bomb\(\)\s*\{.*bomb.*\|.*bomb)/i,
      remediation: 'Remove self-replicating recursive processes.',
    });

    this.addRule({
      id: 'SHELL-004',
      name: 'Global Unrestricted Permission Override',
      category: 'SHELL',
      description: 'Matches recursive 777 permission escalation across system roots.',
      severity: 'HIGH',
      pattern: /(chmod\s+(-R\s+|--recursive\s+)777\s+(\/|~|C:\\|\/etc|\/usr))|(takeown\s+\/f\s+C:\\\s+\/r)/i,
      remediation: 'Use least-privilege explicit permission masks scoped to target files.',
    });

    this.addRule({
      id: 'SHELL-005',
      name: 'Unverified Remote Code Execution Pipe',
      category: 'SHELL',
      description: 'Matches dangerous piping from curl/wget directly to bash/sh.',
      severity: 'HIGH',
      pattern: /(curl|wget)\s+[^\n|;]+\|\s*(sudo\s+)?(ba)?sh/i,
      remediation: 'Download scripts to a temporary file, inspect contents, and execute explicitly with approval.',
    });

    // 2. SQL DESTRUCTIVE MUTATION RULES
    this.addRule({
      id: 'SQL-001',
      name: 'Destructive SQL Drop Database or Schema',
      category: 'SQL',
      description: 'Matches DROP DATABASE or DROP SCHEMA statements.',
      severity: 'CRITICAL',
      pattern: /\bDROP\s+(DATABASE|SCHEMA)\s+(IF\s+EXISTS\s+)?[a-zA-Z0-9_`"[\]]+/i,
      remediation: 'Database and schema drops require human operator authorization.',
    });

    this.addRule({
      id: 'SQL-002',
      name: 'Destructive SQL Drop or Truncate Table',
      category: 'SQL',
      description: 'Matches DROP TABLE or TRUNCATE TABLE statements.',
      severity: 'CRITICAL',
      pattern: /\b(DROP\s+TABLE|TRUNCATE(\s+TABLE)?)\s+(IF\s+EXISTS\s+)?[a-zA-Z0-9_`".\[\]]+/i,
      remediation: 'Use soft-deletes or migration rollback scripts instead of raw table destruction.',
    });

    this.addRule({
      id: 'SQL-003',
      name: 'Unbounded SQL Delete Without Where Clause',
      category: 'SQL',
      description: 'Matches DELETE FROM statements that lack WHERE clause or use trivial WHERE 1=1.',
      severity: 'HIGH',
      pattern: /\bDELETE\s+FROM\s+[a-zA-Z0-9_`".\[\]]+\s*(;|$|WHERE\s+(1=1|true|'1'='1'|\bTRUE\b)\s*(;|$))/i,
      remediation: 'Include specific, parameterized WHERE clauses when deleting database rows.',
    });

    this.addRule({
      id: 'SQL-004',
      name: 'SQL Drop Column Statement',
      category: 'SQL',
      description: 'Matches ALTER TABLE ... DROP COLUMN operations.',
      severity: 'HIGH',
      pattern: /\bALTER\s+TABLE\s+[a-zA-Z0-9_`".\[\]]+\s+DROP\s+(COLUMN\s+)?[a-zA-Z0-9_`"[\]]+/i,
      remediation: 'Deprecate columns gracefully or run through formal migration review.',
    });

    // 3. GIT REPOSITORY RISK RULES
    this.addRule({
      id: 'GIT-001',
      name: 'Git Force Push Attempt',
      category: 'GIT',
      description: 'Matches git push with --force or -f flags.',
      severity: 'CRITICAL',
      pattern: /\bgit\s+push\s+[^\n;]*(-f\b|--force\b|--force-with-lease\b)/i,
      remediation: 'Use standard fast-forward git pushes or rebase cleanly before pushing.',
    });

    this.addRule({
      id: 'GIT-002',
      name: 'Git Hard Reset',
      category: 'GIT',
      description: 'Matches git reset --hard which can discard uncommitted or upstream commits.',
      severity: 'HIGH',
      pattern: /\bgit\s+reset\s+--hard\b/i,
      remediation: 'Use git stash or soft reset (git reset --soft) to preserve working tree history.',
    });

    this.addRule({
      id: 'GIT-003',
      name: 'Git Aggressive Untracked Clean',
      category: 'GIT',
      description: 'Matches git clean -fdx or similar aggressive untracked file deletion.',
      severity: 'HIGH',
      pattern: /\bgit\s+clean\s+(-[a-zA-Z]*f[a-zA-Z]*d[a-zA-Z]*x|--force\s+-d\s+-x)/i,
      remediation: 'Use git status and manually remove specific generated artifacts.',
    });

    this.addRule({
      id: 'GIT-004',
      name: 'Protected Branch Deletion',
      category: 'GIT',
      description: 'Matches branch deletion commands targeting main, master, prod, or release branches.',
      severity: 'CRITICAL',
      pattern: /\bgit\s+(branch\s+(-D|-d)|push\s+[^\s]+\s+:)\s*(main|master|prod|production|release|staging)\b/i,
      remediation: 'Protected branches must not be deleted by autonomous agents.',
    });

    // 4. CLOUD INFRASTRUCTURE DELETION RULES
    this.addRule({
      id: 'CLOUD-001',
      name: 'GCP Project Deletion or Bulk GCS Removal',
      category: 'CLOUD',
      description: 'Matches gcloud projects delete or gsutil rm -r targeting root buckets.',
      severity: 'CRITICAL',
      pattern: /(gcloud\s+projects\s+delete)|(gsutil\s+rm\s+(-r|-R)\s+gs:\/\/)|(gcloud\s+storage\s+rm\s+(--recursive|-r)\s+gs:\/\/)/i,
      remediation: 'Cloud project or bucket deletion must be performed manually by organization admins.',
    });

    this.addRule({
      id: 'CLOUD-002',
      name: 'AWS S3 Force Bucket Removal or RDS Deletion',
      category: 'CLOUD',
      description: 'Matches aws s3 rb --force or aws rds delete-db-instance.',
      severity: 'CRITICAL',
      pattern: /(aws\s+s3\s+rb\s+s3:\/\/[^\s]+\s+--force)|(aws\s+rds\s+delete-db-instance)|(aws\s+dynamodb\s+delete-table)/i,
      remediation: 'Database and bucket teardowns require multi-party verification.',
    });

    this.addRule({
      id: 'CLOUD-003',
      name: 'Azure Resource Group Deletion',
      category: 'CLOUD',
      description: 'Matches az group delete commands.',
      severity: 'CRITICAL',
      pattern: /az\s+group\s+delete\b/i,
      remediation: 'Resource group teardown should be managed via governed IaC pipelines.',
    });

    this.addRule({
      id: 'CLOUD-004',
      name: 'Infrastructure As Code Full Destroy',
      category: 'CLOUD',
      description: 'Matches terraform destroy, tofu destroy, or pulumi destroy.',
      severity: 'CRITICAL',
      pattern: /\b(terraform|tofu|pulumi)\s+destroy\b/i,
      remediation: 'IaC destruction plans require explicit engineer approval and state backups.',
    });

    // 5. KUBERNETES DESTRUCTION RULES
    this.addRule({
      id: 'K8S-001',
      name: 'Kubernetes Namespace or Bulk Resource Purge',
      category: 'KUBERNETES',
      description: 'Matches kubectl delete ns or kubectl delete all --all.',
      severity: 'CRITICAL',
      pattern: /kubectl\s+delete\s+(ns\b|namespace\b|namespaces\b|all\s+--all\b)/i,
      remediation: 'Delete specific namespaced pods or deployments instead of entire namespaces.',
    });
  }

  public addRule(rule: InterceptorRule): void {
    this.rules.push(rule);
  }

  public getRules(): ReadonlyArray<InterceptorRule> {
    return this.rules;
  }

  public inspect(command: string): InterceptorMatch[] {
    if (!command || typeof command !== 'string') {
      return [];
    }

    const matches: InterceptorMatch[] = [];
    const trimmed = command.trim();

    for (const rule of this.rules) {
      if (typeof rule.pattern === 'function') {
        if (rule.pattern(trimmed)) {
          matches.push({
            ruleId: rule.id,
            ruleName: rule.name,
            category: rule.category,
            severity: rule.severity,
            description: rule.description,
            matchedText: trimmed.slice(0, 120),
            remediation: rule.remediation,
          });
        }
      } else if (rule.pattern instanceof RegExp) {
        const regexMatch = trimmed.match(rule.pattern);
        if (regexMatch) {
          matches.push({
            ruleId: rule.id,
            ruleName: rule.name,
            category: rule.category,
            severity: rule.severity,
            description: rule.description,
            matchedText: regexMatch[0],
            remediation: rule.remediation,
          });
        }
      }
    }

    return matches;
  }

  public isDestructive(command: string): boolean {
    const matches = this.inspect(command);
    return matches.some((m) => m.severity === 'CRITICAL' || m.severity === 'HIGH');
  }
}
