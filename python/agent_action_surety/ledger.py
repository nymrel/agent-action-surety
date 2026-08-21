"""
Agent Action Surety - Cryptographic Audit Ledger & Receipt Generator (Python Engine)
Generates tamper-evident SHA-256 Merkle-linked action receipts.
Zero external dependencies.
Copyright (c) 2026 Nymrel / JalenBuilds LLC.
"""

import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Any, Dict, List, Optional, Tuple
from .types import ActionEnvelope, ActionReceipt, PolicyEvaluationResult, PolicyDecision


class ExecutionLedger:
    GENESIS_PREV_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

    def __init__(self, session_id: Optional[str] = None, hmac_secret: Optional[str] = None):
        self.session_id = session_id or f"session_{int(time.time() * 1000)}_{secrets.token_hex(4)}"
        self.hmac_secret = hmac_secret
        self.receipt_history: List[ActionReceipt] = []
        self.last_receipt_hash = self.GENESIS_PREV_HASH

    def get_session_id(self) -> str:
        return self.session_id

    def get_history(self) -> List[ActionReceipt]:
        return list(self.receipt_history)

    @staticmethod
    def canonicalize_data(data: Dict[str, Any]) -> str:
        """Deterministic JSON string for cryptographic hashing."""
        filtered = {k: v for k, v in data.items() if v is not None}
        return json.dumps(filtered, sort_keys=True, separators=(",", ":"))

    @staticmethod
    def sha256(content: str) -> str:
        """Compute SHA-256 hex digest of UTF-8 content."""
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    @staticmethod
    def hmac_sha256(content: str, secret: str) -> str:
        """Compute HMAC-SHA256 signature."""
        return hmac.new(secret.encode("utf-8"), content.encode("utf-8"), hashlib.sha256).hexdigest()

    def record_action(
        self, action: ActionEnvelope, evaluation: PolicyEvaluationResult
    ) -> ActionReceipt:
        """Record policy evaluation and emit cryptographically linked ActionReceipt."""
        timestamp = evaluation.timestamp or int(time.time() * 1000)
        receipt_id = f"rcpt_{timestamp}_{secrets.token_hex(4)}"
        action_id = action.id or f"act_{timestamp}_{secrets.token_hex(3)}"
        prev_receipt_hash = self.last_receipt_hash

        decision_str = evaluation.decision.value if isinstance(evaluation.decision, PolicyDecision) else str(evaluation.decision)
        action_type_str = action.action_type.value if hasattr(action.action_type, "value") else str(action.action_type)
        command_summary = action.command[:160] if action.command else None

        payload_to_hash: Dict[str, Any] = {
            "actionId": action_id,
            "actionType": action_type_str,
            "commandSummary": command_summary,
            "decision": decision_str,
            "metadata": action.metadata or {},
            "prevReceiptHash": prev_receipt_hash,
            "receiptId": receipt_id,
            "sessionId": self.session_id,
            "targetPath": action.target_path,
            "timestamp": timestamp,
            "violationsCount": len(evaluation.violations),
        }

        canonical_string = self.canonicalize_data(payload_to_hash)
        receipt_hash = self.sha256(canonical_string)

        signature: Optional[str] = None
        if self.hmac_secret:
            signature = self.hmac_sha256(receipt_hash, self.hmac_secret)

        metadata = dict(action.metadata or {})
        metadata["parentOrganization"] = "Nymrel -> JalenBuilds LLC"
        metadata["verifiableTrust"] = True

        receipt = ActionReceipt(
            receipt_id=receipt_id,
            session_id=self.session_id,
            action_id=action_id,
            action_type=action_type_str,
            decision=decision_str,
            violations_count=len(evaluation.violations),
            prev_receipt_hash=prev_receipt_hash,
            receipt_hash=receipt_hash,
            timestamp=timestamp,
            command_summary=command_summary,
            target_path=action.target_path,
            signature=signature,
            metadata=metadata,
        )

        self.receipt_history.append(receipt)
        self.last_receipt_hash = receipt_hash

        return receipt

    @classmethod
    def verify_receipt(cls, receipt: ActionReceipt, hmac_secret: Optional[str] = None) -> bool:
        """Verify integrity of a single receipt against its hash and HMAC signature."""
        payload_to_hash: Dict[str, Any] = {
            "actionId": receipt.action_id,
            "actionType": receipt.action_type,
            "commandSummary": receipt.command_summary,
            "decision": receipt.decision,
            "metadata": receipt.metadata or {},
            "prevReceiptHash": receipt.prev_receipt_hash,
            "receiptId": receipt.receipt_id,
            "sessionId": receipt.session_id,
            "targetPath": receipt.target_path,
            "timestamp": receipt.timestamp,
            "violationsCount": receipt.violations_count,
        }

        canonical_string = cls.canonicalize_data(payload_to_hash)
        expected_hash = cls.sha256(canonical_string)

        if receipt.receipt_hash != expected_hash:
            return False

        if hmac_secret:
            if not receipt.signature:
                return False
            expected_sig = cls.hmac_sha256(expected_hash, hmac_secret)
            if not hmac.compare_digest(receipt.signature, expected_sig):
                return False

        return True

    @classmethod
    def verify_chain(
        cls, receipts: List[ActionReceipt], hmac_secret: Optional[str] = None
    ) -> Tuple[bool, Optional[int], Optional[str]]:
        """Verify entire chain of receipts for tamper-evidence."""
        if not receipts:
            return True, None, None

        expected_prev_hash = cls.GENESIS_PREV_HASH

        for i, receipt in enumerate(receipts):
            if receipt.prev_receipt_hash != expected_prev_hash:
                return (
                    False,
                    i,
                    f"Chain broken at index {i}: prev_receipt_hash does not match previous hash.",
                )

            if not cls.verify_receipt(receipt, hmac_secret):
                return False, i, f"Receipt integrity verification failed at index {i}."

            expected_prev_hash = receipt.receipt_hash

        return True, None, None

    def export_jsonl(self) -> str:
        """Export all recorded receipts formatted as JSON Lines."""
        return "\n".join(json.dumps(r.to_dict()) for r in self.receipt_history)
