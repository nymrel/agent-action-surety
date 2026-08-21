"""
Unit Tests: CLI Engine (Python Engine)
Zero external dependencies.
"""

import json
import os
import unittest
from agent_action_surety.cli import main
from agent_action_surety.ledger import ExecutionLedger


class TestCli(unittest.TestCase):
    def test_cli_check_safe_command(self):
        exit_code = main(["check", "--cmd", "echo safe command"])
        self.assertEqual(exit_code, 0)

    def test_cli_check_dangerous_command(self):
        exit_code = main(["check", "--cmd", "rm -rf /"])
        self.assertEqual(exit_code, 1)

    def test_cli_path_allowed(self):
        exit_code = main(["path", "--target", "./pyproject.toml"])
        self.assertEqual(exit_code, 0)

    def test_cli_path_sensitive_blocked(self):
        exit_code = main(["path", "--target", "./.env"])
        self.assertEqual(exit_code, 1)

    def test_cli_verify_receipt(self):
        temp_receipt_file = "temp_receipt_py_test.json"
        fake_receipt = {
            "receiptId": "rcpt_999999_pytest",
            "sessionId": "session_pytest",
            "actionId": "act_999_py",
            "actionType": "exec",
            "decision": "ALLOW",
            "violationsCount": 0,
            "prevReceiptHash": ExecutionLedger.GENESIS_PREV_HASH,
            "commandSummary": "echo python test",
            "timestamp": 1770000000000,
            "metadata": {},
        }
        payload = {
            "actionId": fake_receipt["actionId"],
            "actionType": fake_receipt["actionType"],
            "commandSummary": fake_receipt["commandSummary"],
            "decision": fake_receipt["decision"],
            "metadata": fake_receipt["metadata"],
            "prevReceiptHash": fake_receipt["prevReceiptHash"],
            "receiptId": fake_receipt["receiptId"],
            "sessionId": fake_receipt["sessionId"],
            "targetPath": None,
            "timestamp": fake_receipt["timestamp"],
            "violationsCount": 0,
        }
        fake_receipt["receiptHash"] = ExecutionLedger.sha256(ExecutionLedger.canonicalize_data(payload))

        with open(temp_receipt_file, "w", encoding="utf-8") as f:
            json.dump(fake_receipt, f)

        try:
            exit_code = main(["verify-receipt", "--file", temp_receipt_file])
            self.assertEqual(exit_code, 0)
        finally:
            if os.path.exists(temp_receipt_file):
                os.remove(temp_receipt_file)


if __name__ == "__main__":
    unittest.main()
