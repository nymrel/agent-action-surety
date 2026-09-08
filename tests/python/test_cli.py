"""
Unit Tests: CLI Engine (Python Engine)
Zero external dependencies.
"""

import json
import os
import sys
import tempfile
import unittest
from agent_action_surety import (
    ActionEnvelope,
    PolicyEngine,
    parse_command_argv,
    wrap_execution,
)
from agent_action_surety.cli import main
from agent_action_surety.ledger import ExecutionLedger


class TestCli(unittest.TestCase):
    def test_cli_check_safe_command(self):
        exit_code = main(["check", "--cmd", "echo safe command"])
        self.assertEqual(exit_code, 0)

    def test_cli_check_dangerous_command(self):
        exit_code = main(["check", "--cmd", "rm -rf /"])
        self.assertEqual(exit_code, 1)

    def test_cli_check_unparseable_command(self):
        exit_code = main(["check", "--cmd", 'tool "unterminated'])
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

    def test_parse_command_argv_portable_contract(self):
        self.assertEqual(
            parse_command_argv(r'''tool "two words" 'three words' C:\path ""'''),
            ["tool", "two words", "three words", r"C:\path", ""],
        )
        self.assertEqual(
            parse_command_argv(r'''tool "quote: \" and slash: \\"'''),
            ["tool", 'quote: " and slash: \\'],
        )

    def test_parse_command_argv_rejects_invalid_inputs(self):
        invalid_commands = (
            "   \t\r\n",
            '""',
            'tool "unterminated',
            "tool\x00arg",
            f"tool {'x' * 32_768}",
        )
        for command in invalid_commands:
            with self.subTest(command_length=len(command)):
                with self.assertRaises(ValueError):
                    parse_command_argv(command)

    def test_wrap_execution_does_not_interpret_shell_chain(self):
        with tempfile.TemporaryDirectory(prefix="surety-no-shell-") as temp_dir:
            marker = os.path.join(temp_dir, "must-not-exist.txt")
            first_script = "import sys; sys.stdout.write('surety-ok')"
            second_script = f"from pathlib import Path; Path({marker!r}).write_text('owned')"
            command = " ".join(
                (
                    json.dumps(sys.executable),
                    "-c",
                    json.dumps(first_script),
                    "&&",
                    json.dumps(sys.executable),
                    "-c",
                    json.dumps(second_script),
                )
            )
            engine = PolicyEngine(
                capabilities=["exec:modify"],
                allowed_paths=[temp_dir],
            )

            result = wrap_execution(
                engine,
                ActionEnvelope(
                    action_type="exec",
                    command=command,
                    working_dir=temp_dir,
                ),
            )

            self.assertTrue(result.evaluation.allowed)
            self.assertTrue(result.success)
            self.assertEqual(result.exit_code, 0)
            self.assertEqual(result.output, "surety-ok")
            self.assertFalse(os.path.exists(marker))

    def test_wrap_execution_denies_chain_after_read_only_prefix(self):
        with tempfile.TemporaryDirectory(prefix="surety-read-only-") as temp_dir:
            marker = os.path.join(temp_dir, "must-not-exist.txt")
            writer = f"from pathlib import Path; Path({marker!r}).write_text('owned')"
            command = " ".join(
                (
                    "python --version",
                    "&&",
                    json.dumps(sys.executable),
                    "-c",
                    json.dumps(writer),
                )
            )
            engine = PolicyEngine(
                capabilities=["exec:read_only"],
                allowed_paths=[temp_dir],
            )

            result = wrap_execution(
                engine,
                ActionEnvelope(
                    action_type="exec",
                    command=command,
                    working_dir=temp_dir,
                ),
            )

            self.assertFalse(result.evaluation.allowed)
            self.assertEqual(
                result.evaluation.capabilities_required,
                ["exec:modify"],
            )
            self.assertFalse(result.success)
            self.assertFalse(os.path.exists(marker))

    def test_wrap_execution_decodes_child_bytes_without_locale_failures(self):
        engine = PolicyEngine(capabilities=["exec:modify"])
        success_script = (
            "import sys; "
            "sys.stdout.buffer.write('surety-✓'.encode('utf-8'))"
        )
        success = wrap_execution(
            engine,
            ActionEnvelope(
                action_type="exec",
                command=" ".join(
                    (json.dumps(sys.executable), "-c", json.dumps(success_script))
                ),
            ),
        )

        self.assertTrue(success.success)
        self.assertEqual(success.exit_code, 0)
        self.assertEqual(success.output, "surety-✓")

        failure_script = (
            "import sys; "
            "sys.stderr.buffer.write(bytes([255]) + b'broken'); "
            "sys.exit(7)"
        )
        failure = wrap_execution(
            engine,
            ActionEnvelope(
                action_type="exec",
                command=" ".join(
                    (json.dumps(sys.executable), "-c", json.dumps(failure_script))
                ),
            ),
        )

        self.assertFalse(failure.success)
        self.assertEqual(failure.exit_code, 7)
        self.assertEqual(failure.error, "�broken")

    def test_parse_failure_records_deny_before_custom_execution(self):
        engine = PolicyEngine(capabilities=["exec:modify"])
        executor_called = []

        def executor(_action, _evaluation):
            executor_called.append(True)
            return "unexpected"

        result = wrap_execution(
            engine,
            ActionEnvelope(action_type="exec", command='tool "unterminated'),
            executor=executor,
        )

        self.assertEqual(executor_called, [])
        self.assertFalse(result.success)
        self.assertFalse(result.evaluation.allowed)
        self.assertEqual(result.evaluation.decision.value, "DENY")
        self.assertEqual(result.receipt.decision, "DENY")
        self.assertIn("denied by surety command parser", result.error.lower())


if __name__ == "__main__":
    unittest.main()
