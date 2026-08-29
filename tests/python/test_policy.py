"""
Unit Tests: Policy Engine & Capability Envelope (Python Engine)
Zero external dependencies.
"""

import os
import time
import unittest
from agent_action_surety import wrap_execution
from agent_action_surety.policy import PolicyEngine
from agent_action_surety.types import ActionEnvelope, PolicyDecision


class TestPolicyEngine(unittest.TestCase):
    def test_enforces_deny_by_default_capabilities(self):
        engine = PolicyEngine(
            capabilities=["fs:read"],  # Only fs:read granted
            allowed_paths=[os.getcwd()],
        )

        read_res = engine.evaluate(
            ActionEnvelope(action_type="fs_read", target_path="./pyproject.toml")
        )
        self.assertTrue(read_res.allowed)
        self.assertEqual(read_res.decision, PolicyDecision.ALLOW)

        write_res = engine.evaluate(
            ActionEnvelope(action_type="fs_write", target_path="./pyproject.toml")
        )
        self.assertFalse(write_res.allowed)
        self.assertEqual(write_res.decision, PolicyDecision.DENY)
        self.assertTrue("Missing required capabilities" in write_res.reasons[0])

    def test_supports_wildcard_capability(self):
        engine = PolicyEngine(
            capabilities=["fs:*"],
            allowed_paths=[os.getcwd()],
        )

        res = engine.evaluate(
            ActionEnvelope(action_type="fs_write", target_path="./test_out.txt")
        )
        self.assertTrue(res.allowed)

    def test_enforces_spend_budget(self):
        engine = PolicyEngine(
            capabilities=["exec:read_only"],
            max_spend_usd=1.0,
        )

        res1 = engine.evaluate(
            ActionEnvelope(action_type="exec", command="echo 1", estimated_cost_usd=0.60)
        )
        self.assertTrue(res1.allowed)
        self.assertEqual(engine.get_accumulated_spend_usd(), 0.60)

        # Excess spend denied
        res2 = engine.evaluate(
            ActionEnvelope(action_type="exec", command="echo 2", estimated_cost_usd=0.50)
        )
        self.assertFalse(res2.allowed)
        self.assertTrue("Spend budget exceeded" in res2.reasons[0])

    def test_enforces_rate_limits(self):
        engine = PolicyEngine(
            capabilities=["exec:read_only"],
            rate_limit_per_minute=3,
        )

        now = time.time() * 1000
        self.assertTrue(engine.evaluate(ActionEnvelope(action_type="exec", command="echo 1", timestamp=int(now))).allowed)
        self.assertTrue(engine.evaluate(ActionEnvelope(action_type="exec", command="echo 2", timestamp=int(now))).allowed)
        self.assertTrue(engine.evaluate(ActionEnvelope(action_type="exec", command="echo 3", timestamp=int(now))).allowed)

        # 4th action exceeds rate limit
        res4 = engine.evaluate(ActionEnvelope(action_type="exec", command="echo 4", timestamp=int(now)))
        self.assertFalse(res4.allowed)
        self.assertTrue("Rate limit exceeded" in res4.reasons[0])

    def test_helper_capable_ripgrep_and_git_require_exec_modify(self):
        commands = [
            "rg needle README.md",
            "rg --no-config --pre helper needle README.md",
            "rg --no-config --hostname-bin helper needle README.md",
            "rg --no-config -z needle archive.gz",
            "rg --no-config --search-zip=true needle archive.gz",
            "rg -- --no-config README.md",
            "rg -e --no-config README.md",
            "rg -n --no-config needle README.md",
            "echo ok && git status",
            "echo ok|git commit",
            "echo $(git status)",
            "rg --no-config needle README.md && git status",
            "npm --version",
            "python --version",
            "hostname changed-host",
            "git status",
            "git diff --ext-diff",
            "git diff --textconv",
            "Git status",
            '"git" status',
        ]

        for command in commands:
            with self.subTest(command=command):
                engine = PolicyEngine(capabilities=["exec:read_only", "git:read"])
                executor_called = []

                def executor(_action, _evaluation):
                    executor_called.append(True)
                    return "unexpected"

                result = wrap_execution(
                    engine,
                    ActionEnvelope(action_type="exec", command=command),
                    executor=executor,
                )
                self.assertFalse(result.evaluation.allowed)
                self.assertIn("exec:modify", result.evaluation.capabilities_required)
                self.assertEqual(executor_called, [])

    def test_only_bounded_no_config_ripgrep_is_read_only(self):
        engine = PolicyEngine(capabilities=["exec:read_only"])
        result = engine.evaluate(
            ActionEnvelope(
                action_type="exec",
                command="rg --no-config needle README.md",
            )
        )
        self.assertTrue(result.allowed)
        self.assertEqual(result.capabilities_required, ["exec:read_only"])

        hostname = engine.evaluate(
            ActionEnvelope(action_type="exec", command="hostname")
        )
        self.assertTrue(hostname.allowed)
        self.assertEqual(hostname.capabilities_required, ["exec:read_only"])

    def test_explicit_git_action_requires_exec_modify(self):
        engine = PolicyEngine(capabilities=["git:read"])
        result = engine.evaluate(
            ActionEnvelope(action_type="git", command="git status")
        )
        self.assertFalse(result.allowed)
        self.assertEqual(result.capabilities_required, ["exec:modify", "git:read"])

    def test_recognizes_quoted_and_case_varied_direct_git_capabilities(self):
        engine = PolicyEngine(capabilities=[])

        self.assertEqual(
            engine.infer_required_capabilities(
                ActionEnvelope(
                    action_type="exec",
                    command='"Git" push --force-with-lease',
                )
            ),
            ["exec:privileged", "git:force_push"],
        )
        for command in (
            "git push -vd origin branch",
            "git push -dv origin branch",
        ):
            with self.subTest(command=command):
                self.assertEqual(
                    engine.infer_required_capabilities(
                        ActionEnvelope(action_type="exec", command=command)
                    ),
                    ["exec:privileged", "git:force_push"],
                )
        self.assertEqual(
            engine.infer_required_capabilities(
                ActionEnvelope(
                    action_type="exec",
                    command=r"C:\Tools\Git.exe commit -m message",
                )
            ),
            ["exec:modify", "git:commit"],
        )
        self.assertEqual(
            engine.infer_required_capabilities(
                ActionEnvelope(
                    action_type="exec",
                    command=r"C:\Tools\Git.exe push -fv origin main",
                )
            ),
            ["exec:privileged", "git:force_push"],
        )
        self.assertEqual(
            engine.infer_required_capabilities(
                ActionEnvelope(
                    action_type="exec",
                    command="git push origin +main",
                )
            ),
            ["exec:privileged", "git:force_push"],
        )
        self.assertEqual(
            engine.infer_required_capabilities(
                ActionEnvelope(
                    action_type="exec",
                    command="git reset --hard HEAD~1",
                )
            ),
            ["exec:privileged", "git:commit"],
        )
        for command in (
            '"Git" reset --hard HEAD~1',
            r"C:\Tools\Git.exe reset --hard HEAD~1",
            "git -C repo reset --hard HEAD~1",
        ):
            with self.subTest(command=command):
                self.assertEqual(
                    engine.infer_required_capabilities(
                        ActionEnvelope(action_type="exec", command=command)
                    ),
                    ["exec:privileged", "git:commit"],
                )
        self.assertEqual(
            engine.infer_required_capabilities(
                ActionEnvelope(action_type="git", command="reset --hard HEAD~1")
            ),
            ["exec:privileged", "git:commit"],
        )
        self.assertEqual(
            engine.infer_required_capabilities(
                ActionEnvelope(
                    action_type="exec",
                    command="git branch --delete main",
                )
            ),
            ["exec:privileged", "git:commit"],
        )
        self.assertEqual(
            engine.infer_required_capabilities(
                ActionEnvelope(
                    action_type="exec",
                    command="git config status changed",
                )
            ),
            ["exec:modify", "git:commit"],
        )
        self.assertEqual(
            engine.infer_required_capabilities(
                ActionEnvelope(
                    action_type="exec",
                    command="git --no-pager status",
                )
            ),
            ["exec:modify", "git:read"],
        )
        self.assertEqual(
            engine.infer_required_capabilities(
                ActionEnvelope(
                    action_type="exec",
                    command="git -c color.ui=false status",
                )
            ),
            ["exec:modify", "git:read"],
        )
        self.assertEqual(
            engine.infer_required_capabilities(
                ActionEnvelope(
                    action_type="exec",
                    command="git unknown-subcommand",
                )
            ),
            ["exec:modify", "git:commit"],
        )


if __name__ == "__main__":
    unittest.main()
