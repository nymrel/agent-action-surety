"""
Unit Tests: Filesystem Path Sandbox (Python Engine)
Zero external dependencies.
"""

import os
import unittest
from agent_action_surety.sandbox import SuretySandbox


class TestSuretySandbox(unittest.TestCase):
    def setUp(self):
        self.root_dir = os.path.abspath("./sandbox_test_py_root")
        self.read_only_dir = os.path.join(self.root_dir, "vendor")
        self.sandbox = SuretySandbox(
            workspace_roots=[self.root_dir],
            read_only_roots=[self.read_only_dir],
        )

    def test_allows_path_within_workspace(self):
        target = os.path.join(self.root_dir, "src", "module.py")
        allowed, norm_p, is_ro, reason = self.sandbox.validate_path(target, is_write=False)
        self.assertTrue(allowed)

    def test_blocks_path_traversal_parent_escape(self):
        target = os.path.join(self.root_dir, "..", "..", "etc", "passwd")
        allowed, norm_p, is_ro, reason = self.sandbox.validate_path(target, is_write=False)
        self.assertFalse(allowed)
        self.assertTrue("traversal" in reason.lower() or "outside allowed" in reason.lower())

    def test_blocks_sensitive_env_file(self):
        target = os.path.join(self.root_dir, ".env")
        allowed, norm_p, is_ro, reason = self.sandbox.validate_path(target, is_write=False)
        self.assertFalse(allowed)
        self.assertTrue("sensitive" in reason.lower())

    def test_blocks_sensitive_ssh_key(self):
        target = os.path.join(self.root_dir, ".ssh", "id_rsa")
        allowed, norm_p, is_ro, reason = self.sandbox.validate_path(target, is_write=False)
        self.assertFalse(allowed)

    def test_enforces_read_only_constraints(self):
        ro_target = os.path.join(self.read_only_dir, "lib.py")

        # Read is allowed
        allowed_read, _, is_ro, _ = self.sandbox.validate_path(ro_target, is_write=False)
        self.assertTrue(allowed_read)
        self.assertTrue(is_ro)

        # Write is rejected
        allowed_write, _, _, reason = self.sandbox.validate_path(ro_target, is_write=True)
        self.assertFalse(allowed_write)
        self.assertTrue("read-only" in reason.lower())


if __name__ == "__main__":
    unittest.main()
