"""
Agent Action Surety (agent_action_surety)
Zero-dependency, dual-language execution firewall & safety policy envelope for AI coding agents.
Copyright (c) 2026 Nymrel / JalenBuilds LLC.
"""

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
    "wrap_execution",
]


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

    # Default shell command execution if action is 'exec' and command exists
    if action.action_type in ("exec", ActionType.EXEC) and action.command:
        cwd = action.working_dir or os.getcwd()
        try:
            proc = subprocess.run(
                action.command,
                shell=True,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=30,
            )
            duration_ms = int((time.time() - start_time) * 1000)
            return ExecutionResult(
                success=proc.returncode == 0,
                evaluation=evaluation,
                receipt=receipt,
                output=proc.stdout,
                error=proc.stderr if proc.returncode != 0 else None,
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
