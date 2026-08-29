"""
Agent Action Surety - CLI Engine (Python)
Command line firewall wrapper and policy validator.
Zero external dependencies.
Copyright (c) 2026 Nymrel / JalenBuilds LLC.
"""

import argparse
import json
import os
import sys
from typing import List, Optional

from .ledger import ExecutionLedger
from .policy import PolicyEngine
from .types import ActionEnvelope, ActionReceipt, PolicyDecision


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-surety",
        description="Agent Action Surety: Zero-dependency execution firewall, sandbox & audit ledger.",
    )
    subparsers = parser.add_subparsers(dest="command", help="Subcommand to execute")

    # exec subcommand
    exec_parser = subparsers.add_parser("exec", help="Evaluate and execute command if permitted")
    exec_parser.add_argument("--cmd", "-c", required=True, help="Command string to execute")
    exec_parser.add_argument("--allowed-paths", help="Comma-separated allowed root directories")
    exec_parser.add_argument("--read-only", help="Comma-separated read-only paths")
    exec_parser.add_argument("--spend-cap", type=float, default=50.0, help="Max spend cap in USD")
    exec_parser.add_argument("--rate-limit", type=int, default=120, help="Max actions per minute")
    exec_parser.add_argument("--allow-destructive", action="store_true", help="Permit dangerous commands")
    exec_parser.add_argument("--secret", help="HMAC secret for receipt signing")
    exec_parser.add_argument("--json", action="store_true", help="Format output as JSON")

    # check subcommand
    check_parser = subparsers.add_parser("check", help="Dry-run evaluate command without execution")
    check_parser.add_argument("--cmd", "-c", required=True, help="Command string to inspect")
    check_parser.add_argument("--allow-destructive", action="store_true", help="Permit dangerous commands")
    check_parser.add_argument("--secret", help="HMAC secret for receipt signing")
    check_parser.add_argument("--json", action="store_true", help="Format output as JSON")

    # path subcommand
    path_parser = subparsers.add_parser("path", help="Validate filesystem path against sandbox")
    path_parser.add_argument("--target", "-t", required=True, help="Target filesystem path")
    path_parser.add_argument("--write", "-w", action="store_true", help="Check as write operation")
    path_parser.add_argument("--allowed-paths", help="Comma-separated allowed root directories")
    path_parser.add_argument("--read-only", help="Comma-separated read-only paths")
    path_parser.add_argument("--json", action="store_true", help="Format output as JSON")

    # verify-receipt subcommand
    vr_parser = subparsers.add_parser("verify-receipt", help="Verify single action receipt")
    vr_parser.add_argument("--file", "-f", required=True, help="Path to receipt JSON file")
    vr_parser.add_argument("--secret", help="HMAC secret for signature check")
    vr_parser.add_argument("--json", action="store_true", help="Format output as JSON")

    # verify-ledger subcommand
    vl_parser = subparsers.add_parser("verify-ledger", help="Verify Merkle chain in ledger JSONL")
    vl_parser.add_argument("--file", "-f", required=True, help="Path to ledger JSONL file")
    vl_parser.add_argument("--secret", help="HMAC secret for signature check")
    vl_parser.add_argument("--json", action="store_true", help="Format output as JSON")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    allowed_paths = (
        [p.strip() for p in args.allowed_paths.split(",")]
        if hasattr(args, "allowed_paths") and args.allowed_paths
        else [os.getcwd()]
    )
    read_only_paths = (
        [p.strip() for p in args.read_only.split(",")]
        if hasattr(args, "read_only") and args.read_only
        else []
    )
    allow_destructive = getattr(args, "allow_destructive", False)
    secret = getattr(args, "secret", None)
    as_json = getattr(args, "json", False)

    caps = ["fs:read", "fs:write", "exec:read_only", "exec:modify"]
    if allow_destructive:
        caps.extend(["exec:privileged", "cloud:delete", "git:force_push"])

    engine = PolicyEngine(
        capabilities=caps,
        allowed_paths=allowed_paths,
        read_only_paths=read_only_paths,
        allow_destructive_commands=allow_destructive,
        hmac_secret=secret or "",
    )
    ledger = ExecutionLedger(hmac_secret=secret)

    if args.command == "check":
        action = ActionEnvelope(action_type="exec", command=args.cmd)
        from . import wrap_execution

        result = wrap_execution(
            engine,
            action,
            ledger=ledger,
            executor=lambda _action, _evaluation: None,
        )
        evaluation = result.evaluation
        receipt = result.receipt

        if as_json:
            print(json.dumps({"evaluation": evaluation.to_dict(), "receipt": receipt.to_dict()}, indent=2))
        else:
            print("\n[AGENT ACTION SURETY EVALUATION]")
            print(f"Command:  {args.cmd}")
            print(f"Decision: {evaluation.decision}")
            print(f"Allowed:  {'YES (SAFE)' if evaluation.allowed else 'NO (BLOCKED)'}")
            if evaluation.reasons:
                print("Reasons:")
                for r in evaluation.reasons:
                    print(f"  - {r}")
            if evaluation.violations:
                print("Violations:")
                for v in evaluation.violations:
                    print(f"  - [{v.category}] {v.rule_name} ({v.severity})")
            print(f"Receipt Hash: {receipt.receipt_hash}\n")

        return 0 if evaluation.allowed else 1

    if args.command == "exec":
        action = ActionEnvelope(action_type="exec", command=args.cmd, working_dir=os.getcwd())
        from . import wrap_execution

        result = wrap_execution(engine, action, ledger=ledger)

        if as_json:
            print(
                json.dumps(
                    {
                        "success": result.success,
                        "evaluation": result.evaluation.to_dict(),
                        "receipt": result.receipt.to_dict(),
                        "output": result.output,
                        "error": result.error,
                        "exitCode": result.exit_code,
                        "executionTimeMs": result.execution_time_ms,
                    },
                    indent=2,
                )
            )
        else:
            if not result.success:
                print("\n[SURETY FIREWALL: EXECUTION BLOCKED]", file=sys.stderr)
                print(f"Command:   {args.cmd}", file=sys.stderr)
                print(f"Error:     {result.error}", file=sys.stderr)
                if result.evaluation.violations:
                    print("Violations:", file=sys.stderr)
                    for v in result.evaluation.violations:
                        print(f"  - [{v.category}] {v.rule_name} ({v.severity}): {v.description}", file=sys.stderr)
                        if v.remediation:
                            print(f"    Remediation: {v.remediation}", file=sys.stderr)
                print(f"Receipt Hash: {result.receipt.receipt_hash}\n", file=sys.stderr)
                return 1
            else:
                if result.output:
                    sys.stdout.write(str(result.output))
                print(
                    f"\n[SURETY: SUCCESS] (Receipt: {result.receipt.receipt_hash[:16]}... | Time: {result.execution_time_ms}ms)"
                )
        return result.exit_code if result.exit_code is not None else (0 if result.success else 1)

    if args.command == "path":
        action = ActionEnvelope(
            action_type="fs_write" if args.write else "fs_read",
            target_path=args.target,
        )
        evaluation = engine.evaluate(action)
        receipt = ledger.record_action(action, evaluation)

        if as_json:
            print(json.dumps({"evaluation": evaluation.to_dict(), "receipt": receipt.to_dict()}, indent=2))
        else:
            print("\n[SURETY PATH VALIDATION]")
            print(f"Target:    {args.target}")
            print(f"Operation: {'WRITE' if args.write else 'READ'}")
            print(f"Allowed:   {'YES (WITHIN SANDBOX)' if evaluation.allowed else 'NO (RESTRICTED)'}")
            if evaluation.reasons:
                for r in evaluation.reasons:
                    print(f"  - {r}")
            print(f"Receipt:   {receipt.receipt_hash}\n")

        return 0 if evaluation.allowed else 1

    if args.command == "verify-receipt":
        try:
            with open(args.file, "r", encoding="utf-8") as f:
                data = json.load(f)
            # Reconstruct ActionReceipt dataclass
            receipt = ActionReceipt(
                receipt_id=data["receiptId"],
                session_id=data["sessionId"],
                action_id=data["actionId"],
                action_type=data["actionType"],
                decision=data["decision"],
                violations_count=data["violationsCount"],
                prev_receipt_hash=data["prevReceiptHash"],
                receipt_hash=data["receiptHash"],
                timestamp=data["timestamp"],
                command_summary=data.get("commandSummary"),
                target_path=data.get("targetPath"),
                signature=data.get("signature"),
                metadata=data.get("metadata", {}),
            )
            valid = ExecutionLedger.verify_receipt(receipt, hmac_secret=secret)
            if as_json:
                print(json.dumps({"valid": valid, "receiptId": receipt.receipt_id}))
            else:
                print("\n[RECEIPT VERIFICATION]")
                print(f"Receipt ID: {receipt.receipt_id}")
                print(f"Valid:      {'VERIFIED (AUTHENTIC)' if valid else 'FAILED (TAMPERED)'}\n")
            return 0 if valid else 1
        except Exception as e:
            print(f"Verification error: {e}", file=sys.stderr)
            return 1

    if args.command == "verify-ledger":
        try:
            receipts: List[ActionReceipt] = []
            with open(args.file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    data = json.loads(line)
                    receipts.append(
                        ActionReceipt(
                            receipt_id=data["receiptId"],
                            session_id=data["sessionId"],
                            action_id=data["actionId"],
                            action_type=data["actionType"],
                            decision=data["decision"],
                            violations_count=data["violationsCount"],
                            prev_receipt_hash=data["prevReceiptHash"],
                            receipt_hash=data["receiptHash"],
                            timestamp=data["timestamp"],
                            command_summary=data.get("commandSummary"),
                            target_path=data.get("targetPath"),
                            signature=data.get("signature"),
                            metadata=data.get("metadata", {}),
                        )
                    )
            valid, broken_idx, reason = ExecutionLedger.verify_chain(receipts, hmac_secret=secret)
            if as_json:
                print(json.dumps({"valid": valid, "count": len(receipts), "brokenIndex": broken_idx, "reason": reason}))
            else:
                print("\n[LEDGER CHAIN VERIFICATION]")
                print(f"Total Receipts: {len(receipts)}")
                print(f"Chain Valid:    {'VERIFIED (TAMPER-EVIDENT MERKLE CHAIN INTACT)' if valid else 'CORRUPTED / BROKEN'}")
                if not valid:
                    print(f"Broken at index {broken_idx}: {reason}", file=sys.stderr)
                print()
            return 0 if valid else 1
        except Exception as e:
            print(f"Ledger verification error: {e}", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
