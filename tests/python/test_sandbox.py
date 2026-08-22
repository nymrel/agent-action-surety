"""
Unit Tests: Filesystem Path Sandbox (Python Engine)
Zero external dependencies.
"""

import os
import shutil
import tempfile
import unittest
from agent_action_surety.sandbox import SuretySandbox


class CountingSandbox(SuretySandbox):
    """SuretySandbox that counts canonicalize_path invocations."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.canonicalize_calls = 0

    def canonicalize_path(self, target_path):
        # getattr guard: the base constructor calls this before subclass
        # attributes assigned after super().__init__() exist.
        self.canonicalize_calls = getattr(self, "canonicalize_calls", 0) + 1
        return super().canonicalize_path(target_path)


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


class TestIntraCallCanonicalizationDedup(unittest.TestCase):
    def setUp(self):
        self.root_dir = os.path.abspath("./sandbox_test_py_root")
        self.read_only_dir = os.path.join(self.root_dir, "vendor")

    def _counting_sandbox(self):
        sb = CountingSandbox(
            workspace_roots=[self.root_dir],
            read_only_roots=[self.read_only_dir],
        )
        sb.canonicalize_calls = 0  # exclude constructor root canonicalization
        return sb

    def test_canonicalizes_once_for_allowed_call(self):
        sb = self._counting_sandbox()
        allowed, _, _, _ = sb.validate_path(os.path.join(self.root_dir, "src", "module.py"))
        self.assertTrue(allowed)
        self.assertEqual(sb.canonicalize_calls, 1)

    def test_canonicalizes_once_for_traversal_denied_call(self):
        sb = CountingSandbox(workspace_roots=[self.root_dir])
        sb.canonicalize_calls = 0
        target = os.path.join(self.root_dir, "..", "..", "etc", "passwd")
        allowed, _, _, _ = sb.validate_path(target)
        self.assertFalse(allowed)
        self.assertEqual(sb.canonicalize_calls, 1)

    def test_blocks_double_encoded_traversal_with_one_canonicalization(self):
        sb = CountingSandbox(workspace_roots=[self.root_dir])
        sb.canonicalize_calls = 0
        target = os.path.join(self.root_dir, "%252e%252e", "outside.txt")
        result = sb.validate_path(target, False)
        self.assertFalse(result[0])
        self.assertEqual(sb.canonicalize_calls, 1)

    def test_preserves_subclass_security_hook_overrides(self):
        class DenyAllSandbox(SuretySandbox):
            def is_sensitive_path(self, target_path):
                return True

        sb = DenyAllSandbox(workspace_roots=[self.root_dir])
        result = sb.validate_path(os.path.join(self.root_dir, "otherwise-safe.txt"), False)
        self.assertFalse(result[0])
        self.assertIn("sensitive path blocked", result[3])

    def test_preserves_custom_deny_patterns_over_once_decoded_path(self):
        sb = SuretySandbox(
            workspace_roots=[self.root_dir], denied_patterns=[r"blocked%2fname$"]
        )
        result = sb.validate_path(
            os.path.join(self.root_dir, "blocked%252fname"), False
        )
        self.assertFalse(result[0])
        self.assertIn("sensitive path blocked", result[3])

    def test_fails_closed_on_otherwise_safe_multi_layer_encoded_paths(self):
        sb = SuretySandbox(workspace_roots=[self.root_dir])
        result = sb.validate_path(
            os.path.join(self.root_dir, "vault%252fchild"), False
        )
        self.assertFalse(result[0])
        self.assertIn("Multi-layer URI encoding", result[3])

    def test_no_cross_call_caching(self):
        sb = CountingSandbox(workspace_roots=[self.root_dir])
        sb.canonicalize_calls = 0
        target = os.path.join(self.root_dir, "a.py")
        self.assertTrue(sb.validate_path(target)[0])
        self.assertTrue(sb.validate_path(target)[0])
        self.assertEqual(sb.canonicalize_calls, 2)

    def test_reduces_work_versus_public_helper_composition(self):
        # Reproduces the pre-dedup call graph using only public helpers.
        naive = CountingSandbox(
            workspace_roots=[self.root_dir], read_only_roots=[self.read_only_dir]
        )
        naive.canonicalize_calls = 0
        target = os.path.join(self.root_dir, "src", "module.py")
        canonical = naive.canonicalize_path(target)
        naive.is_sensitive_path(target)
        naive.is_sensitive_path(canonical)
        for root in [self.root_dir]:
            naive.is_path_contained(canonical, root)
        for ro_root in [self.read_only_dir]:
            naive.is_path_contained(canonical, ro_root)

        fast = self._counting_sandbox()
        fast.validate_path(target)

        self.assertEqual(fast.canonicalize_calls, 1)
        self.assertLess(fast.canonicalize_calls, naive.canonicalize_calls)

    def test_preserves_validation_outcomes(self):
        sb = self._counting_sandbox()

        allowed, _, is_ro, _ = sb.validate_path(os.path.join(self.root_dir, "src", "module.py"))
        self.assertTrue(allowed)
        self.assertFalse(is_ro)

        s_allowed, _, _, s_reason = sb.validate_path(os.path.join(self.root_dir, ".env"))
        self.assertFalse(s_allowed)
        self.assertIn("sensitive", s_reason.lower())

        t_allowed, _, _, t_reason = sb.validate_path(os.path.join(self.root_dir, "..", "outside.py"))
        self.assertFalse(t_allowed)
        self.assertIn("traversal detected", t_reason.lower())

        ro_allowed, _, ro_flag, _ = sb.validate_path(
            os.path.join(self.read_only_dir, "lib.py"), is_write=False
        )
        self.assertTrue(ro_allowed)
        self.assertTrue(ro_flag)

        w_allowed, _, _, w_reason = sb.validate_path(
            os.path.join(self.read_only_dir, "new.py"), is_write=True
        )
        self.assertFalse(w_allowed)
        self.assertIn("read-only", w_reason.lower())

    def test_blocks_symlinked_sensitive_path(self):
        ws_root = tempfile.mkdtemp(prefix="surety-ws-")
        outside_root = tempfile.mkdtemp(prefix="surety-out-")
        try:
            secret_dir = os.path.join(outside_root, ".ssh")
            os.mkdir(secret_dir)
            with open(os.path.join(secret_dir, "id_rsa"), "w") as f:
                f.write("secret")
            link = os.path.join(ws_root, "sshlink")
            try:
                os.symlink(secret_dir, link, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation not permitted on this platform")

            sb = SuretySandbox(workspace_roots=[ws_root])
            allowed, _, _, reason = sb.validate_path(os.path.join(link, "id_rsa"))
            self.assertFalse(allowed)
            self.assertIn("sensitive", reason.lower())
        finally:
            shutil.rmtree(ws_root, ignore_errors=True)
            shutil.rmtree(outside_root, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
