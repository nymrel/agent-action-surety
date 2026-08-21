"""
Agent Action Surety - Command & SQL Interceptors (Python Engine)
Deep pattern inspection for destructive operations.
Zero external dependencies.
Copyright (c) 2026 Nymrel / JalenBuilds LLC.
"""

import re
from typing import Callable, List, Optional, Union
from .types import InterceptorMatch, InterceptorRule


class CommandInterceptor:
    def __init__(self, custom_rules: Optional[List[InterceptorRule]] = None):
        self.rules: List[InterceptorRule] = []
        self._init_default_rules()
        if custom_rules:
            self.rules.extend(custom_rules)

    def _init_default_rules(self) -> None:
        # 1. SHELL & FILESYSTEM DESTRUCTION
        self.add_rule(
            InterceptorRule(
                id="SHELL-001",
                name="Root or Wildcard Recursive Deletion",
                category="SHELL",
                description="Matches attempts to recursively delete system root, home, current dir, or wildcards.",
                severity="CRITICAL",
                pattern=r"(rm\s+-(r|rf|fr|f\s+-r)\s+(\/|~|\$HOME|\*|\.\s|\.\/\*|C:\\|\/boot|\/etc|\/usr|\/var))|(rmdir\s+\/(s|q)\s+(C:\\|\/|\\))|(del\s+\/[fsq\s]+\s*(C:\\|\*|\.\*))",
                remediation="Scope deletions to an explicit relative directory inside the project sandbox.",
            )
        )

        self.add_rule(
            InterceptorRule(
                id="SHELL-002",
                name="Disk Block Destruction or Format",
                category="SHELL",
                description="Matches raw block device writes or partition formatting (mkfs, dd, format).",
                severity="CRITICAL",
                pattern=r"(mkfs(\.[a-z0-9]+)?\s+\/dev\/)|(dd\s+if=[^\s]+\s+of=\/dev\/(sd[a-z]|nvme|vd[a-z]|disk|rdisk))|(format\s+[a-zA-Z]:\s*\/[qfsy])",
                remediation="Avoid raw disk manipulation from autonomous agent sessions.",
            )
        )

        self.add_rule(
            InterceptorRule(
                id="SHELL-003",
                name="Fork Bomb Signature",
                category="SHELL",
                description="Detects bash/sh fork bomb patterns that cause denial of service.",
                severity="CRITICAL",
                pattern=r"(:(\(\)\s*\{|{\s*:\|:&|\s*:\s*\|\s*:\s*&\s*};\s*:)|bomb\(\)\s*\{.*bomb.*\|.*bomb)",
                remediation="Remove self-replicating recursive processes.",
            )
        )

        self.add_rule(
            InterceptorRule(
                id="SHELL-004",
                name="Global Unrestricted Permission Override",
                category="SHELL",
                description="Matches recursive 777 permission escalation across system roots.",
                severity="HIGH",
                pattern=r"(chmod\s+(-R\s+|--recursive\s+)777\s+(\/|~|C:\\|\/etc|\/usr))|(takeown\s+\/f\s+C:\\\s+\/r)",
                remediation="Use least-privilege explicit permission masks scoped to target files.",
            )
        )

        self.add_rule(
            InterceptorRule(
                id="SHELL-005",
                name="Unverified Remote Code Execution Pipe",
                category="SHELL",
                description="Matches dangerous piping from curl/wget directly to bash/sh.",
                severity="HIGH",
                pattern=r"(curl|wget)\s+[^\n|;]+\|\s*(sudo\s+)?(ba)?sh",
                remediation="Download scripts to a temporary file, inspect contents, and execute explicitly with approval.",
            )
        )

        # 2. SQL DESTRUCTIVE MUTATIONS
        self.add_rule(
            InterceptorRule(
                id="SQL-001",
                name="Destructive SQL Drop Database or Schema",
                category="SQL",
                description="Matches DROP DATABASE or DROP SCHEMA statements.",
                severity="CRITICAL",
                pattern=r"\bDROP\s+(DATABASE|SCHEMA)\s+(IF\s+EXISTS\s+)?[a-zA-Z0-9_`\"\[\]]+",
                remediation="Database and schema drops require human operator authorization.",
            )
        )

        self.add_rule(
            InterceptorRule(
                id="SQL-002",
                name="Destructive SQL Drop or Truncate Table",
                category="SQL",
                description="Matches DROP TABLE or TRUNCATE TABLE statements.",
                severity="CRITICAL",
                pattern=r"\b(DROP\s+TABLE|TRUNCATE(\s+TABLE)?)\s+(IF\s+EXISTS\s+)?[a-zA-Z0-9_`\".\[\]]+",
                remediation="Use soft-deletes or migration rollback scripts instead of raw table destruction.",
            )
        )

        self.add_rule(
            InterceptorRule(
                id="SQL-003",
                name="Unbounded SQL Delete Without Where Clause",
                category="SQL",
                description="Matches DELETE FROM statements that lack WHERE clause or use trivial WHERE 1=1.",
                severity="HIGH",
                pattern=r"\bDELETE\s+FROM\s+[a-zA-Z0-9_`\".\[\]]+\s*(;|$|WHERE\s+(1=1|true|'1'='1'|\bTRUE\b)\s*(;|$))",
                remediation="Include specific, parameterized WHERE clauses when deleting database rows.",
            )
        )

        self.add_rule(
            InterceptorRule(
                id="SQL-004",
                name="SQL Drop Column Statement",
                category="SQL",
                description="Matches ALTER TABLE ... DROP COLUMN operations.",
                severity="HIGH",
                pattern=r"\bALTER\s+TABLE\s+[a-zA-Z0-9_`\".\[\]]+\s+DROP\s+(COLUMN\s+)?[a-zA-Z0-9_`\"\[\]]+",
                remediation="Deprecate columns gracefully or run through formal migration review.",
            )
        )

        # 3. GIT REPOSITORY RISKS
        self.add_rule(
            InterceptorRule(
                id="GIT-001",
                name="Git Force Push Attempt",
                category="GIT",
                description="Matches git push with --force or -f flags.",
                severity="CRITICAL",
                pattern=r"\bgit\s+push\s+[^\n;]*(-f\b|--force\b|--force-with-lease\b)",
                remediation="Use standard fast-forward git pushes or rebase cleanly before pushing.",
            )
        )

        self.add_rule(
            InterceptorRule(
                id="GIT-002",
                name="Git Hard Reset",
                category="GIT",
                description="Matches git reset --hard which can discard uncommitted or upstream commits.",
                severity="HIGH",
                pattern=r"\bgit\s+reset\s+--hard\b",
                remediation="Use git stash or soft reset (git reset --soft) to preserve working tree history.",
            )
        )

        self.add_rule(
            InterceptorRule(
                id="GIT-003",
                name="Git Aggressive Untracked Clean",
                category="GIT",
                description="Matches git clean -fdx or similar aggressive untracked file deletion.",
                severity="HIGH",
                pattern=r"\bgit\s+clean\s+(-[a-zA-Z]*f[a-zA-Z]*d[a-zA-Z]*x|--force\s+-d\s+-x)",
                remediation="Use git status and manually remove specific generated artifacts.",
            )
        )

        self.add_rule(
            InterceptorRule(
                id="GIT-004",
                name="Protected Branch Deletion",
                category="GIT",
                description="Matches branch deletion commands targeting main, master, prod, or release branches.",
                severity="CRITICAL",
                pattern=r"\bgit\s+(branch\s+(-D|-d)|push\s+[^\s]+\s+:)\s*(main|master|prod|production|release|staging)\b",
                remediation="Protected branches must not be deleted by autonomous agents.",
            )
        )

        # 4. CLOUD INFRASTRUCTURE DELETION
        self.add_rule(
            InterceptorRule(
                id="CLOUD-001",
                name="GCP Project Deletion or Bulk GCS Removal",
                category="CLOUD",
                description="Matches gcloud projects delete or gsutil rm -r targeting root buckets.",
                severity="CRITICAL",
                pattern=r"(gcloud\s+projects\s+delete)|(gsutil\s+rm\s+(-r|-R)\s+gs:\/\/)|(gcloud\s+storage\s+rm\s+(--recursive|-r)\s+gs:\/\/)",
                remediation="Cloud project or bucket deletion must be performed manually by organization admins.",
            )
        )

        self.add_rule(
            InterceptorRule(
                id="CLOUD-002",
                name="AWS S3 Force Bucket Removal or RDS Deletion",
                category="CLOUD",
                description="Matches aws s3 rb --force or aws rds delete-db-instance.",
                severity="CRITICAL",
                pattern=r"(aws\s+s3\s+rb\s+s3:\/\/[^\s]+\s+--force)|(aws\s+rds\s+delete-db-instance)|(aws\s+dynamodb\s+delete-table)",
                remediation="Database and bucket teardowns require multi-party verification.",
            )
        )

        self.add_rule(
            InterceptorRule(
                id="CLOUD-003",
                name="Azure Resource Group Deletion",
                category="CLOUD",
                description="Matches az group delete commands.",
                severity="CRITICAL",
                pattern=r"az\s+group\s+delete\b",
                remediation="Resource group teardown should be managed via governed IaC pipelines.",
            )
        )

        self.add_rule(
            InterceptorRule(
                id="CLOUD-004",
                name="Infrastructure As Code Full Destroy",
                category="CLOUD",
                description="Matches terraform destroy, tofu destroy, or pulumi destroy.",
                severity="CRITICAL",
                pattern=r"\b(terraform|tofu|pulumi)\s+destroy\b",
                remediation="IaC destruction plans require explicit engineer approval and state backups.",
            )
        )

        # 5. KUBERNETES DESTRUCTION
        self.add_rule(
            InterceptorRule(
                id="K8S-001",
                name="Kubernetes Namespace or Bulk Resource Purge",
                category="KUBERNETES",
                description="Matches kubectl delete ns or kubectl delete all --all.",
                severity="CRITICAL",
                pattern=r"kubectl\s+delete\s+(ns\b|namespace\b|namespaces\b|all\s+--all\b)",
                remediation="Delete specific namespaced pods or deployments instead of entire namespaces.",
            )
        )

    def add_rule(self, rule: InterceptorRule) -> None:
        self.rules.append(rule)

    def inspect(self, command: str) -> List[InterceptorMatch]:
        if not command or not isinstance(command, str):
            return []

        matches: List[InterceptorMatch] = []
        trimmed = command.strip()

        for rule in self.rules:
            if callable(rule.pattern):
                if rule.pattern(trimmed):
                    matches.append(
                        InterceptorMatch(
                            rule_id=rule.id,
                            rule_name=rule.name,
                            category=rule.category,
                            severity=rule.severity,
                            description=rule.description,
                            matched_text=trimmed[:120],
                            remediation=rule.remediation,
                        )
                    )
            elif isinstance(rule.pattern, str):
                regex_match = re.search(rule.pattern, trimmed, re.IGNORECASE)
                if regex_match:
                    matches.append(
                        InterceptorMatch(
                            rule_id=rule.id,
                            rule_name=rule.name,
                            category=rule.category,
                            severity=rule.severity,
                            description=rule.description,
                            matched_text=regex_match.group(0),
                            remediation=rule.remediation,
                        )
                    )

        return matches

    def is_destructive(self, command: str) -> bool:
        matches = self.inspect(command)
        return any(m.severity in ("CRITICAL", "HIGH") for m in matches)
