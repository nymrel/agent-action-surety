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


MAX_POLICY_COMMAND_CHARACTERS = 32_768
POLICY_ASCII_WHITESPACE = frozenset(" \t\n\r\f\v")
SIMPLE_READ_ONLY_EXECUTABLES = {
    "ls", "dir", "pwd", "echo", "cat", "type", "head", "tail", "grep",
    "findstr", "whoami", "uname",
}
GIT_GLOBAL_OPTIONS_WITH_VALUES = {
    "-c", "-C", "--config-env", "--git-dir", "--work-tree", "--namespace",
    "--super-prefix",
}
GIT_GLOBAL_FLAG_OPTIONS = {
    "-p", "--paginate", "--no-pager", "--bare", "--no-replace-objects",
    "--literal-pathspecs", "--glob-pathspecs", "--noglob-pathspecs",
    "--icase-pathspecs", "--no-optional-locks", "--version", "--help",
}
GIT_READ_ONLY_SUBCOMMANDS = {
    "annotate", "blame", "cat-file", "count-objects", "describe", "diff",
    "diff-files", "diff-index", "diff-tree", "for-each-ref", "log", "ls-files",
    "ls-remote", "ls-tree", "merge-base", "name-rev", "rev-list", "rev-parse",
    "shortlog", "show", "show-branch", "status", "version",
}


def _parse_policy_command_argv(command: str) -> Optional[List[str]]:
    """Mirror the public portable argv grammar and fail closed on ambiguity."""
    if len(command) > MAX_POLICY_COMMAND_CHARACTERS:
        return None

    argv: List[str] = []
    current: List[str] = []
    quote: Optional[str] = None
    token_started = False
    index = 0

    while index < len(command):
        character = command[index]
        code_point = ord(character)
        is_whitespace = character in POLICY_ASCII_WHITESPACE
        is_control = (
            code_point <= 0x1F
            or code_point == 0x7F
            or 0x80 <= code_point <= 0x9F
        )
        if is_control and not is_whitespace:
            return None

        if quote is None:
            if is_whitespace:
                if token_started:
                    argv.append("".join(current))
                    current = []
                    token_started = False
                index += 1
                continue
            if character in ("'", '"'):
                quote = character
                token_started = True
                index += 1
                continue
            current.append(character)
            token_started = True
            index += 1
            continue

        if character == quote:
            quote = None
            index += 1
            continue
        if (
            quote == '"'
            and character == "\\"
            and index + 1 < len(command)
            and command[index + 1] in ('"', "\\")
        ):
            current.append(command[index + 1])
            token_started = True
            index += 2
            continue
        current.append(character)
        token_started = True
        index += 1

    if quote is not None:
        return None
    if token_started:
        argv.append("".join(current))
    if not argv or not argv[0]:
        return None
    return argv


def _ripgrep_argument_can_spawn_helper(argument: str) -> bool:
    lower = argument.lower()
    if (
        lower == "--pre"
        or lower.startswith("--pre=")
        or lower == "--pre-glob"
        or lower.startswith("--pre-glob=")
        or lower == "--hostname-bin"
        or lower.startswith("--hostname-bin=")
        or lower == "--search-zip"
        or lower.startswith("--search-zip=")
    ):
        return True
    return lower.startswith("-") and not lower.startswith("--") and "z" in lower[1:]


def _command_contains_shell_syntax(command: str) -> bool:
    return any(character in command for character in "\r\n;&|<>()`") or "$(" in command or "${" in command


def _is_read_only_command_argv(argv: List[str]) -> bool:
    executable = argv[0].lower()
    args = argv[1:]

    if executable in SIMPLE_READ_ONLY_EXECUTABLES:
        return True
    if executable == "hostname":
        return not args
    if executable == "node":
        return len(args) == 1 and args[0] in ("-v", "--version")
    if executable == "rg":
        # Requiring --no-config in the first argument position prevents it
        # from becoming an option value or a positional after ``--``.
        return bool(args) and args[0].lower() == "--no-config" and not any(
            _ripgrep_argument_can_spawn_helper(arg) for arg in args
        )

    # Git can execute aliases, external diff/textconv helpers, fsmonitor hooks,
    # and pagers from repository, user, or environment configuration.
    return False


def _policy_executable_basename(executable: str) -> str:
    return executable.replace("\\", "/").rsplit("/", 1)[-1].lower()


def _find_git_subcommand(tokens: List[str]) -> Optional[str]:
    index = 0
    while index < len(tokens):
        token = tokens[index]
        lower = token.lower()
        if lower == "--":
            return None
        if token in GIT_GLOBAL_OPTIONS_WITH_VALUES or lower in GIT_GLOBAL_OPTIONS_WITH_VALUES:
            index += 2
            if index > len(tokens):
                return None
            continue
        if lower.startswith((
            "--config-env=", "--git-dir=", "--work-tree=", "--namespace=",
            "--super-prefix=", "--exec-path=",
        )):
            index += 1
            continue
        if lower == "--exec-path" or lower in GIT_GLOBAL_FLAG_OPTIONS:
            index += 1
            continue
        if lower.startswith("-"):
            return None
        return lower
    return None


def _infer_git_capability(command: str) -> str:
    argv = _parse_policy_command_argv(command)
    if argv is None:
        return "git:force_push"

    executable = _policy_executable_basename(argv[0])
    tokens = argv[1:] if executable in ("git", "git.exe") else argv
    lower = [token.lower() for token in tokens]
    subcommand = _find_git_subcommand(tokens)
    is_push = subcommand == "push"

    if any(
        token.startswith("--force")
        or (
            token.startswith("-")
            and not token.startswith("--")
            and "f" in token[1:]
        )
        for token in lower
    ) or (
        is_push
        and any(
            token == "--mirror"
            or token.startswith("--delete")
            or (
                token.startswith("-")
                and not token.startswith("--")
                and "d" in token[1:]
            )
            or token == "--prune"
            or token.startswith("+")
            or token.startswith(":")
            for token in lower
        )
    ):
        return "git:force_push"
    if is_push:
        return "git:push"

    if subcommand is not None and subcommand in GIT_READ_ONLY_SUBCOMMANDS:
        return "git:read"

    # Unknown or locally mutating Git commands fail closed to the only local
    # mutation capability in the public taxonomy.
    return "git:commit"


def _git_command_requires_privileged(command: str, capability: str) -> bool:
    if capability == "git:force_push":
        return True

    argv = _parse_policy_command_argv(command)
    if argv is None:
        return True
    executable = _policy_executable_basename(argv[0])
    tokens = argv[1:] if executable in ("git", "git.exe") else argv
    lower = [token.lower() for token in tokens]
    subcommand = _find_git_subcommand(tokens)

    if subcommand == "reset" and "--hard" in lower:
        return True
    if subcommand == "clean":
        short_flags = "".join(
            token
            for token in lower
            if token.startswith("-") and not token.startswith("--")
        )
        has_force = "--force" in lower or "f" in short_flags
        has_directories = "-d" in lower or "d" in short_flags
        has_ignored = "-x" in lower or "x" in short_flags
        if has_force and has_directories and has_ignored:
            return True
    if subcommand == "branch":
        deletes = any(
            token.lower().startswith("--delete")
            or (
                token.startswith("-")
                and not token.startswith("--")
                and ("d" in token[1:] or "D" in token[1:])
            )
            for token in tokens
        )
        protected_branch = any(
            token in {"main", "master", "prod", "production", "release", "staging"}
            for token in lower
        )
        if deletes and protected_branch:
            return True
    return False


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
            argv = _parse_policy_command_argv(cmd)
            is_direct_git = (
                argv is not None
                and _policy_executable_basename(argv[0]) in ("git", "git.exe")
            )
            git_capability = _infer_git_capability(cmd) if is_direct_git else None
            is_destructive = self.interceptor.is_destructive(cmd) or (
                git_capability is not None
                and _git_command_requires_privileged(cmd, git_capability)
            )
            if is_destructive:
                caps.append("exec:privileged")
            elif self._is_read_only_shell_command(cmd):
                caps.append("exec:read_only")
            else:
                caps.append("exec:modify")

            if git_capability is not None:
                caps.append(git_capability)
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
            cmd = action.command or ""
            git_capability = _infer_git_capability(cmd)
            caps.append(
                "exec:privileged"
                if _git_command_requires_privileged(cmd, git_capability)
                else "exec:modify"
            )
            caps.append(git_capability)
        else:
            caps.append("exec:modify")

        return caps

    def _is_read_only_shell_command(self, cmd: str) -> bool:
        if _command_contains_shell_syntax(cmd):
            return False
        argv = _parse_policy_command_argv(cmd)
        return argv is not None and _is_read_only_command_argv(argv)

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
