"""
Unit Tests: Policy Engine & Capability Envelope (Python Engine)
Zero external dependencies.
"""

import os
import time
import unittest
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


if __name__ == "__main__":
    unittest.main()
