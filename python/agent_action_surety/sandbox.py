"""
Agent Action Surety - Filesystem Path Containment Sandbox (Python Engine)
Prevents directory traversal, symlink escapes, and sensitive credential exfiltration.
Zero external dependencies.
Copyright (c) 2026 Nymrel / JalenBuilds LLC.
"""

import os
import sys
import re
import urllib.parse
from pathlib import Path
from typing import List, Optional, Tuple


class SuretySandbox:
    # Default sensitive credential & system paths to protect
    DEFAULT_SENSITIVE_PATTERNS = [
        r"\.git[/\\]config$",
        r"\.git[/\\]credentials$",
        r"\.git[/\\]hooks[/\\]",
        r"\.env(\.[a-zA-Z0-9_-]+)?$",
        r"[/\\]\.ssh([/\\]|$)",
        r"[/\\]\.aws([/\\]|$)",
        r"[/\\]\.gnupg([/\\]|$)",
        r"[/\\]id_rsa([/\\]|$)",
        r"[/\\]id_ed25519([/\\]|$)",
        r"([/\\])etc([/\\])(passwd|shadow|sudoers)$",
        r"^[a-zA-Z]:[/\\]windows[/\\]system32",
    ]

    def __init__(
        self,
        workspace_roots: Optional[List[str]] = None,
        read_only_roots: Optional[List[str]] = None,
        denied_patterns: Optional[List[str]] = None,
    ):
        roots = workspace_roots if workspace_roots else [os.getcwd()]
        self.workspace_roots = [self.canonicalize_path(r) for r in roots]
        self.read_only_roots = [self.canonicalize_path(r) for r in (read_only_roots or [])]

        combined_patterns = self.DEFAULT_SENSITIVE_PATTERNS + (denied_patterns or [])
        self.denied_patterns = [re.compile(p, re.IGNORECASE) for p in combined_patterns]
        self.is_windows = sys.platform.startswith("win")

    def canonicalize_path(self, target_path: str) -> str:
        """Canonicalize and normalize a path for secure comparison."""
        if not target_path or not isinstance(target_path, str):
            return ""

        # Decode percent encoding
        decoded = target_path
        if "%" in decoded:
            try:
                decoded = urllib.parse.unquote(decoded)
            except Exception:
                pass

        # Expand user and resolve
        expanded = os.path.expanduser(decoded)
        resolved = os.path.abspath(expanded)
        normalized = os.path.normpath(resolved)

        # Realpath resolution to prevent symlink bypass
        try:
            if os.path.exists(normalized):
                return os.path.realpath(normalized)
            else:
                parent = os.path.dirname(normalized)
                if os.path.exists(parent):
                    real_parent = os.path.realpath(parent)
                    return os.path.join(real_parent, os.path.basename(normalized))
        except Exception:
            pass

        return normalized

    def is_sensitive_path(self, target_path: str) -> bool:
        """Check if a path targets sensitive secrets or system credentials."""
        canonical = self.canonicalize_path(target_path)
        for pattern in self.denied_patterns:
            if pattern.search(canonical) or pattern.search(target_path):
                return True
        return False

    def is_path_contained(self, target_path: str, root_path: str) -> bool:
        """Check whether target_path is strictly contained within root_path."""
        canonical_target = self.canonicalize_path(target_path)
        canonical_root = self.canonicalize_path(root_path)

        if self.is_windows:
            t_low = canonical_target.lower()
            r_low = canonical_root.lower()
            if t_low == r_low:
                return True
            try:
                rel = os.path.relpath(t_low, r_low)
                return not rel.startswith("..") and not os.path.isabs(rel)
            except ValueError:
                # Different drive letters on Windows
                return False
        else:
            if canonical_target == canonical_root:
                return True
            try:
                rel = os.path.relpath(canonical_target, canonical_root)
                return not rel.startswith("..") and not os.path.isabs(rel)
            except ValueError:
                return False

    def validate_path(
        self, target_path: str, is_write: bool = False
    ) -> Tuple[bool, str, bool, Optional[str]]:
        """
        Validate path against workspace boundaries, read-only constraints, and sensitive patterns.
        Returns: (allowed, normalized_path, is_read_only, reason)
        """
        if not target_path or not isinstance(target_path, str):
            return False, "", False, "Empty or invalid path provided."

        # Traversal pattern check
        if ".." in target_path or "%2e%2e" in target_path.lower():
            canonical = self.canonicalize_path(target_path)
            if not any(self.is_path_contained(canonical, root) for root in self.workspace_roots):
                return (
                    False,
                    canonical,
                    False,
                    f'Path traversal detected: "{target_path}" resolves outside configured workspace roots.',
                )

        canonical = self.canonicalize_path(target_path)

        # 1. Check sensitive path deny-list
        if self.is_sensitive_path(target_path) or self.is_sensitive_path(canonical):
            return (
                False,
                canonical,
                False,
                f'Access to sensitive path blocked by safety policy: "{target_path}".',
            )

        # 2. Check workspace containment
        if not any(self.is_path_contained(canonical, root) for root in self.workspace_roots):
            return (
                False,
                canonical,
                False,
                f'Path "{target_path}" is outside allowed workspace roots.',
            )

        # 3. Check read-only constraints
        is_read_only = any(
            self.is_path_contained(canonical, ro_root) for ro_root in self.read_only_roots
        )

        if is_write and is_read_only:
            return (
                False,
                canonical,
                True,
                f'Write rejected: path "{target_path}" is located within a read-only root.',
            )

        return True, canonical, is_read_only, None
