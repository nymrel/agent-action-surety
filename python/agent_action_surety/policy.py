"""
Agent Action Surety - Policy Engine & Envelope (Python Engine)
Deny-by-default capability gates, spend caps, rate limits, and safety envelope.
Zero external dependencies.
Copyright (c) 2026 Nymrel / JalenBuilds LLC.
"""

import os
import time
from typing import Any, Dict, List, Optional, Set, Tuple
from .types import (
    ActionCapability,
    ActionEnvelope,
    ActionType,
    InterceptorMatch,
    InterceptorRule,
    PolicyDecision,
    PolicyEvaluationResult,
)
from .sandbox import SuretySandbox
from .interceptors import CommandInterceptor


class PolicyEngine:
    def __init__(
        self,
        capabilities: Optional[List[str]] = None,
        allowed_paths: Optional[List[str]] = None,
        read_only_paths: Optional[List[str]] = None,
        denied_path_patterns: Optional[List[str]] = None,
        max_spend_usd: float = 50.0,
        max_tokens: int = 1_000_000,
        rate_limit_per_minute: int = 120,
        allow_destructive_commands: bool = False,
        custom_rules: Optional[List[InterceptorRule]] = None,
        hmac_secret: str = "",
        session_id: str = "",
        environment: str = "development",
    ):
        self.capabilities: Set[str] = set(capabilities or ["fs:read", "exec:read_only"])
        self.allowed_paths = allowed_paths or [os.getcwd()]
        self.read_only_paths = read_only_paths or []
        self.denied_path_patterns = denied_path_patterns or []
        self.max_spend_usd = max_spend_usd
        self.max_tokens = max_tokens
        self.rate_limit_per_minute = rate_limit_per_minute
        self.allow_destructive_commands = allow_destructive_commands
        self.hmac_secret = hmac_secret
        self.session_id = session_id
        self.environment = environment

        self.sandbox = SuretySandbox(
            workspace_roots=self.allowed_paths,
            read_only_roots=self.read_only_paths,
            denied_patterns=self.denied_path_patterns,
        )

        self.interceptor = CommandInterceptor(custom_rules)

        self.action_timestamps: List[float] = []
        self.total_spend_usd: float = 0.0
        self.total_tokens_used: int = 0

    def get_sandbox(self) -> SuretySandbox:
        return self.sandbox

    def get_interceptor(self) -> CommandInterceptor:
        return self.interceptor

    def get_accumulated_spend_usd(self) -> float:
        return self.total_spend_usd

    def get_accumulated_tokens(self) -> int:
        return self.total_tokens_used

    def has_capability(self, cap: str) -> bool:
        """Check if a capability is granted by policy (including wildcards e.g. fs:*)."""
        if cap in self.capabilities:
            return True
        if ":" in cap:
            family = cap.split(":", 1)[0]
            if f"{family}:*" in self.capabilities:
                return True
        return False

    def _check_rate_limit(self, now_ms: float) -> Tuple[bool, int]:
        one_minute_ago = now_ms - 60_000
        self.action_timestamps = [t for t in self.action_timestamps if t > one_minute_ago]
        count = len(self.action_timestamps)
        if count >= self.rate_limit_per_minute:
            return False, count
        return True, count

    def infer_required_capabilities(self, action: ActionEnvelope) -> List[str]:
        caps: List[str] = []
        action_type = (
            action.action_type.value
            if hasattr(action.action_type, "value")
            else str(action.action_type).lower()
        )

        if action_type == "fs_read":
            caps.append("fs:read")
        elif action_type == "fs_write":
            caps.append("fs:write")
        elif action_type == "fs_delete":
            caps.append("fs:delete")
        elif action_type == "exec":
            cmd = (action.command or "").strip()
            is_destructive = self.interceptor.is_destructive(cmd)
            if is_destructive:
                caps.append("exec:privileged")
            elif self._is_read_only_shell_command(cmd):
                caps.append("exec:read_only")
            else:
                caps.append("exec:modify")

            if cmd.startswith("git "):
                if "--force" in cmd or " -f" in cmd:
                    caps.append("git:force_push")
                elif cmd.startswith("git push"):
                    caps.append("git:push")
                elif cmd.startswith("git commit"):
                    caps.append("git:commit")
                else:
                    caps.append("git:read")
        elif action_type == "net":
            caps.append("net:http")
        elif action_type == "db":
            cmd = (action.command or "").upper()
            if "DROP" in cmd or "TRUNCATE" in cmd:
                caps.append("db:destructive")
            elif "ALTER" in cmd or "CREATE" in cmd:
                caps.append("db:schema_migrate")
            else:
                caps.append("db:query")
        elif action_type == "cloud":
            cmd = (action.command or "").lower()
            if any(k in cmd for k in ["delete", "destroy", "terminate"]):
                caps.append("cloud:delete")
            elif any(k in cmd for k in ["create", "apply", "provision"]):
                caps.append("cloud:provision")
            else:
                caps.append("cloud:read")
        elif action_type == "git":
            cmd = (action.command or "").lower()
            if "--force" in cmd or "-f" in cmd:
                caps.append("git:force_push")
            elif "push" in cmd:
                caps.append("git:push")
            elif "commit" in cmd:
                caps.append("git:commit")
            else:
                caps.append("git:read")
        else:
            caps.append("exec:modify")

        return caps

    def _is_read_only_shell_command(self, cmd: str) -> bool:
        read_only_prefixes = [
            "ls", "dir", "pwd", "echo", "cat", "type", "head", "tail", "grep", "rg",
            "findstr", "node -v", "npm -v", "python --version", "git status", "git log",
            "git diff", "git branch", "whoami", "uname", "hostname"
        ]
        lower = cmd.lower().strip()
        return any(lower == p or lower.startswith(p + " ") for p in read_only_prefixes)

    def evaluate(self, action: ActionEnvelope) -> PolicyEvaluationResult:
        now_ms = float(action.timestamp or (time.time() * 1000))
        reasons: List[str] = []
        violations: List[InterceptorMatch] = []
        decision = PolicyDecision.ALLOW
        normalized_path: Optional[str] = None

        # 1. Check Rate Limits
        rate_ok, rate_count = self._check_rate_limit(now_ms)
        if not rate_ok:
            reasons.append(
                f"Rate limit exceeded: {rate_count} actions performed in the last 60 seconds (limit: {self.rate_limit_per_minute}/min)."
            )
            return PolicyEvaluationResult(
                decision=PolicyDecision.DENY,
                allowed=False,
                reasons=reasons,
                violations=[],
                capabilities_required=[],
                timestamp=int(now_ms),
            )

        # 2. Check Spend & Token Bounds
        cost = float(action.estimated_cost_usd or 0.0)
        if self.total_spend_usd + cost > self.max_spend_usd:
            reasons.append(
                f"Spend budget exceeded: requested ${cost:.4f} would exceed remaining cap of ${(self.max_spend_usd - self.total_spend_usd):.4f}."
            )
            return PolicyEvaluationResult(
                decision=PolicyDecision.DENY,
                allowed=False,
                reasons=reasons,
                violations=[],
                capabilities_required=[],
                timestamp=int(now_ms),
            )

        tokens = int(action.tokens_requested or 0)
        if self.total_tokens_used + tokens > self.max_tokens:
            reasons.append(
                f"Token limit exceeded: requested {tokens} tokens exceeds remaining quota of {self.max_tokens - self.total_tokens_used}."
            )
            return PolicyEvaluationResult(
                decision=PolicyDecision.DENY,
                allowed=False,
                reasons=reasons,
                violations=[],
                capabilities_required=[],
                timestamp=int(now_ms),
            )

        # 3. Capability Enforcement
        required_caps = self.infer_required_capabilities(action)
        missing_caps = [c for c in required_caps if not self.has_capability(c)]

        if missing_caps:
            decision = PolicyDecision.DENY
            reasons.append(
                f"Missing required capabilities: [{', '.join(missing_caps)}]. Granted: [{', '.join(sorted(self.capabilities))}]."
            )

        # 4. Filesystem Path Sandbox
        if action.target_path:
            is_write = action.action_type in ("fs_write", "fs_delete", ActionType.FS_WRITE, ActionType.FS_DELETE)
            p_allowed, norm_p, is_ro, p_reason = self.sandbox.validate_path(action.target_path, is_write=is_write)
            normalized_path = norm_p
            if not p_allowed:
                decision = PolicyDecision.DENY
                reasons.append(p_reason or f'Path validation failed for "{action.target_path}".')

        # 5. Command Interceptors
        if action.command:
            matches = self.interceptor.inspect(action.command)
            if matches:
                violations.extend(matches)
                has_critical = any(m.severity == "CRITICAL" for m in matches)
                has_high = any(m.severity == "HIGH" for m in matches)

                if has_critical or (not self.allow_destructive_commands and has_high):
                    decision = PolicyDecision.DENY
                    for m in matches:
                        reasons.append(
                            f"[{m.category}] Blocked: {m.rule_name} ({m.description}). Remediation: {m.remediation or 'None'}"
                        )
                elif has_high:
                    decision = PolicyDecision.REQUIRE_HUMAN_APPROVAL
                    reasons.append("High severity command requires human confirmation.")

        allowed = decision == PolicyDecision.ALLOW
        if allowed:
            self.action_timestamps.append(now_ms)
            self.total_spend_usd += cost
            self.total_tokens_used += tokens
            if not reasons:
                reasons.append("Action passed all surety safety gates.")

        return PolicyEvaluationResult(
            decision=decision,
            allowed=allowed,
            reasons=reasons,
            violations=violations,
            capabilities_required=required_caps,
            normalized_path=normalized_path,
            spend_approved_usd=cost if allowed else 0.0,
            tokens_approved=tokens if allowed else 0,
            timestamp=int(now_ms),
        )
