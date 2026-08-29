"""
Agent Action Surety (agent_action_surety)
Zero-dependency, dual-language execution firewall & safety policy envelope for AI coding agents.
Copyright (c) 2026 Nymrel / JalenBuilds LLC.
"""

import os
import subprocess
import time
from typing import Any, Callable, Optional, Union

from .types import (
    ActionCapability,
    ActionEnvelope,
    ActionReceipt,
    ActionType,
    ExecutionResult,
    InterceptorCategory,
    InterceptorMatch,
    InterceptorRule,
    PolicyDecision,
    PolicyEvaluationResult,
)
from .sandbox import SuretySandbox
from .interceptors import CommandInterceptor
from .ledger import ExecutionLedger
from .policy import PolicyEngine

__version__ = "1.0.0"
__author__ = "Nymrel / JalenBuilds LLC <contact@nymrel.com>"

__all__ = [
    "ActionCapability",
    "ActionEnvelope",
    "ActionReceipt",
    "ActionType",
    "CommandInterceptor",
    "ExecutionLedger",
    "ExecutionResult",
    "InterceptorCategory",
    "InterceptorMatch",
    "InterceptorRule",
    "PolicyDecision",
    "PolicyEngine",
    "PolicyEvaluationResult",
    "SuretySandbox",
    "create_receipt",
    "evaluate_policy",
    "parse_command_argv",
    "wrap_execution",
]


MAX_COMMAND_CHARACTERS = 32_768
ASCII_WHITESPACE = frozenset(" \t\n\r\f\v")


def parse_command_argv(command: str) -> list[str]:
    """Parse the portable command-string API into argv without a shell."""
    if len(command) > MAX_COMMAND_CHARACTERS:
        raise ValueError(
            f"Command exceeds the {MAX_COMMAND_CHARACTERS}-character safety limit."
        )

    argv: list[str] = []
    current: list[str] = []
    quote: Optional[str] = None
    token_started = False
    index = 0

    while index < len(command):
        character = command[index]
        code_point = ord(character)
        is_whitespace = character in ASCII_WHITESPACE
        is_control = (
            code_point <= 0x1F
            or code_point == 0x7F
            or 0x80 <= code_point <= 0x9F
        )

        if is_control and not is_whitespace:
            raise ValueError(
                "Command contains a disallowed control character "
                f"(U+{code_point:04X})."
            )

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
        raise ValueError("Command contains an unterminated quoted argument.")

    if token_started:
        argv.append("".join(current))

    if not argv:
        raise ValueError("Command must include an executable.")
    if not argv[0]:
        raise ValueError("Command executable must not be empty.")

    return argv


def evaluate_policy(
    policy_or_engine: Union[PolicyEngine, dict], action: ActionEnvelope
) -> PolicyEvaluationResult:
    """Quick evaluation of an action envelope against a policy config or engine."""
    if isinstance(policy_or_engine, PolicyEngine):
        engine = policy_or_engine
    else:
        engine = PolicyEngine(**policy_or_engine)
    return engine.evaluate(action)


def create_receipt(
    action: ActionEnvelope,
    evaluation: PolicyEvaluationResult,
    ledger_or_secret: Optional[Union[ExecutionLedger, str]] = None,
) -> ActionReceipt:
    """Create a standalone cryptographic receipt for an action evaluation."""
    if isinstance(ledger_or_secret, ExecutionLedger):
        ledger = ledger_or_secret
    else:
        ledger = ExecutionLedger(hmac_secret=ledger_or_secret if isinstance(ledger_or_secret, str) else None)
    return ledger.record_action(action, evaluation)


def wrap_execution(
    engine: PolicyEngine,
    action: ActionEnvelope,
    ledger: Optional[ExecutionLedger] = None,
    executor: Optional[Callable[[ActionEnvelope, PolicyEvaluationResult], Any]] = None,
) -> ExecutionResult:
    """
    Wrap and safely execute an action through policy gates, sandbox containment,
    command interceptors, and cryptographic receipt logging.
    """
    active_ledger = ledger or ExecutionLedger(
        session_id=engine.session_id, hmac_secret=engine.hmac_secret
    )

    start_time = time.time()
    command_argv: Optional[list[str]] = None
    is_exec = action.action_type in ("exec", ActionType.EXEC)

    if is_exec:
        try:
            command_argv = parse_command_argv(action.command or "")
        except (TypeError, ValueError) as error:
            evaluation = PolicyEvaluationResult(
                decision=PolicyDecision.DENY,
                allowed=False,
                reasons=[f"Command parsing failed closed: {error}"],
                violations=[],
                capabilities_required=[],
                spend_approved_usd=0.0,
                tokens_approved=0,
                timestamp=action.timestamp or int(time.time() * 1000),
            )
            receipt = active_ledger.record_action(action, evaluation)
            return ExecutionResult(
                success=False,
                evaluation=evaluation,
                receipt=receipt,
                error=f"Action denied by surety command parser: {error}",
                exit_code=1,
                execution_time_ms=int((time.time() - start_time) * 1000),
            )

    evaluation = engine.evaluate(action)
    receipt = active_ledger.record_action(action, evaluation)

    if not evaluation.allowed:
        return ExecutionResult(
            success=False,
            evaluation=evaluation,
            receipt=receipt,
            error=f"Action denied by surety policy: {' | '.join(evaluation.reasons)}",
            execution_time_ms=int((time.time() - start_time) * 1000),
        )

    # Custom executor callback
    if executor:
        try:
            output = executor(action, evaluation)
            return ExecutionResult(
                success=True,
                evaluation=evaluation,
                receipt=receipt,
                output=output,
                execution_time_ms=int((time.time() - start_time) * 1000),
            )
        except Exception as e:
            return ExecutionResult(
                success=False,
                evaluation=evaluation,
                receipt=receipt,
                error=str(e),
                execution_time_ms=int((time.time() - start_time) * 1000),
            )

    # Default execution always uses the argv parsed before policy evaluation.
    if is_exec and command_argv:
        cwd = action.working_dir or os.getcwd()
        try:
            proc = subprocess.run(
                command_argv,
                shell=False,
                cwd=cwd,
                capture_output=True,
                text=False,
                timeout=30,
            )
            stdout = (proc.stdout or b"").decode("utf-8", errors="replace")
            stderr = (proc.stderr or b"").decode("utf-8", errors="replace")
            duration_ms = int((time.time() - start_time) * 1000)
            return ExecutionResult(
                success=proc.returncode == 0,
                evaluation=evaluation,
                receipt=receipt,
                output=stdout,
                error=stderr if proc.returncode != 0 else None,
                exit_code=proc.returncode,
                execution_time_ms=duration_ms,
            )
        except Exception as e:
            return ExecutionResult(
                success=False,
                evaluation=evaluation,
                receipt=receipt,
                error=str(e),
                exit_code=1,
                execution_time_ms=int((time.time() - start_time) * 1000),
            )

    return ExecutionResult(
        success=True,
        evaluation=evaluation,
        receipt=receipt,
        execution_time_ms=int((time.time() - start_time) * 1000),
    )
