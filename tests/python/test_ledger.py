"""
Unit Tests: Cryptographic Execution Ledger (Python Engine)
Zero external dependencies.
"""

import unittest
from agent_action_surety.ledger import ExecutionLedger
from agent_action_surety.types import ActionEnvelope, PolicyEvaluationResult, PolicyDecision


class TestExecutionLedger(unittest.TestCase):
    def setUp(self):
        self.secret = "nymrel_secret_python_key_2026"
        self.ledger = ExecutionLedger(hmac_secret=self.secret)

    def test_records_action_and_verifies_receipt(self):
        action = ActionEnvelope(
            action_type="exec",
            command="pytest -v",
            estimated_cost_usd=0.005,
        )
        evaluation = PolicyEvaluationResult(
            decision=PolicyDecision.ALLOW,
            allowed=True,
            reasons=["Permitted safe test run"],
            violations=[],
            capabilities_required=["exec:read_only"],
            timestamp=1770000000000,
        )

        receipt = self.ledger.record_action(action, evaluation)

        self.assertTrue(receipt.receipt_id.startswith("rcpt_"))
        self.assertEqual(receipt.prev_receipt_hash, ExecutionLedger.GENESIS_PREV_HASH)
        self.assertEqual(len(receipt.receipt_hash), 64)
        self.assertIsNotNone(receipt.signature)

        is_valid = ExecutionLedger.verify_receipt(receipt, hmac_secret=self.secret)
        self.assertTrue(is_valid, "Receipt should be verified as authentic")

    def test_detects_receipt_tampering(self):
        action = ActionEnvelope(action_type="fs_read", target_path="./safe.py")
        evaluation = PolicyEvaluationResult(
            decision=PolicyDecision.ALLOW,
            allowed=True,
            reasons=[],
            violations=[],
            capabilities_required=["fs:read"],
            timestamp=1770000000000,
        )

        receipt = self.ledger.record_action(action, evaluation)

        # Alter decision
        receipt.decision = "DENY"
        self.assertFalse(ExecutionLedger.verify_receipt(receipt, hmac_secret=self.secret))

    def test_merkle_chain_integrity_and_tamper_detection(self):
        r1 = self.ledger.record_action(
            ActionEnvelope(action_type="exec", command="echo 1"),
            PolicyEvaluationResult(decision=PolicyDecision.ALLOW, allowed=True, reasons=[], violations=[], capabilities_required=[], timestamp=1000),
        )
        r2 = self.ledger.record_action(
            ActionEnvelope(action_type="exec", command="echo 2"),
            PolicyEvaluationResult(decision=PolicyDecision.ALLOW, allowed=True, reasons=[], violations=[], capabilities_required=[], timestamp=2000),
        )
        r3 = self.ledger.record_action(
            ActionEnvelope(action_type="exec", command="echo 3"),
            PolicyEvaluationResult(decision=PolicyDecision.ALLOW, allowed=True, reasons=[], violations=[], capabilities_required=[], timestamp=3000),
        )

        self.assertEqual(r1.prev_receipt_hash, ExecutionLedger.GENESIS_PREV_HASH)
        self.assertEqual(r2.prev_receipt_hash, r1.receipt_hash)
        self.assertEqual(r3.prev_receipt_hash, r2.receipt_hash)

        history = self.ledger.get_history()
        valid, broken_idx, _ = ExecutionLedger.verify_chain(history, hmac_secret=self.secret)
        self.assertTrue(valid)

        # Corrupt intermediate receipt
        tampered_history = list(history)
        tampered_history[1].command_summary = "malicious alteration"
        valid_broken, broken_idx, reason = ExecutionLedger.verify_chain(tampered_history, hmac_secret=self.secret)
        self.assertFalse(valid_broken)
        self.assertEqual(broken_idx, 1)


if __name__ == "__main__":
    unittest.main()
