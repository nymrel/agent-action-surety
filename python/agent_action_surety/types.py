"""
Agent Action Surety - Core Type Definitions & Dataclasses
Zero-dependency, dual-language execution firewall & safety envelope.
Copyright (c) 2026 Nymrel / JalenBuilds LLC.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Union


ActionCapability = str


class PolicyDecision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_HUMAN_APPROVAL = "REQUIRE_HUMAN_APPROVAL"


class ActionType(str, Enum):
    FS_READ = "fs_read"
    FS_WRITE = "fs_write"
    FS_DELETE = "fs_delete"
    EXEC = "exec"
    NET = "net"
    DB = "db"
    CLOUD = "cloud"
    GIT = "git"


class InterceptorCategory(str, Enum):
    SHELL = "SHELL"
    SQL = "SQL"
    GIT = "GIT"
    CLOUD = "CLOUD"
    KUBERNETES = "KUBERNETES"
    PACKAGE_MGR = "PACKAGE_MGR"


@dataclass
class InterceptorRule:
    id: str
    name: str
    category: str
    description: str
    pattern: Union[str, Callable[[str], bool]]
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    remediation: Optional[str] = None


@dataclass
class InterceptorMatch:
    rule_id: str
    rule_name: str
    category: str
    severity: str
    description: str
    matched_text: Optional[str] = None
    remediation: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ruleId": self.rule_id,
            "ruleName": self.rule_name,
            "category": self.category,
            "severity": self.severity,
            "description": self.description,
            "matchedText": self.matched_text,
            "remediation": self.remediation,
        }


@dataclass
class ActionEnvelope:
    action_type: Union[ActionType, str]
    id: Optional[str] = None
    command: Optional[str] = None
    target_path: Optional[str] = None
    content: Optional[str] = None
    working_dir: Optional[str] = None
    estimated_cost_usd: float = 0.0
    tokens_requested: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: Optional[int] = None


@dataclass
class PolicyEvaluationResult:
    decision: PolicyDecision
    allowed: bool
    reasons: List[str]
    violations: List[InterceptorMatch]
    capabilities_required: List[str]
    normalized_path: Optional[str] = None
    spend_approved_usd: float = 0.0
    tokens_approved: int = 0
    timestamp: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision.value if isinstance(self.decision, PolicyDecision) else self.decision,
            "allowed": self.allowed,
            "reasons": self.reasons,
            "violations": [v.to_dict() for v in self.violations],
            "capabilitiesRequired": self.capabilities_required,
            "normalizedPath": self.normalized_path,
            "spendApprovedUsd": self.spend_approved_usd,
            "tokensApproved": self.tokens_approved,
            "timestamp": self.timestamp,
        }


@dataclass
class ActionReceipt:
    receipt_id: str
    session_id: str
    action_id: str
    action_type: str
    decision: str
    violations_count: int
    prev_receipt_hash: str
    receipt_hash: str
    timestamp: int
    command_summary: Optional[str] = None
    target_path: Optional[str] = None
    signature: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "receiptId": self.receipt_id,
            "sessionId": self.session_id,
            "actionId": self.action_id,
            "actionType": self.action_type,
            "decision": self.decision,
            "commandSummary": self.command_summary,
            "targetPath": self.target_path,
            "violationsCount": self.violations_count,
            "prevReceiptHash": self.prev_receipt_hash,
            "receiptHash": self.receipt_hash,
            "signature": self.signature,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }
        return {k: v for k, v in d.items() if v is not None}


@dataclass
class ExecutionResult:
    success: bool
    evaluation: PolicyEvaluationResult
    receipt: ActionReceipt
    output: Optional[Any] = None
    error: Optional[str] = None
    exit_code: Optional[int] = None
    execution_time_ms: int = 0
