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

        # Decode up to two percent-encoding layers. The previous validation
        # flow canonicalized the target again in downstream helpers, so this
        # preserves double-encoded traversal protection while resolving the
        # filesystem only once.
        decoded = target_path
        for _ in range(2):
            if "%" not in decoded:
                break
            try:
                next_decoded = urllib.parse.unquote(decoded)
                if next_decoded == decoded:
                    break
                decoded = next_decoded
            except Exception:
                break

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
        return self._matches_denied_patterns(canonical, target_path)

    def _matches_denied_patterns(self, canonical: str, raw_input: str) -> bool:
        """Pattern-only sensitive check over an already-canonical path plus its
        raw input. Callers must guarantee `canonical` is the canonical form of
        `raw_input`; no filesystem work happens here."""
        representations = [canonical, raw_input]
        if "%" in raw_input:
            try:
                # Preserve the once-decoded normalized form examined by the
                # legacy helper chain without repeating realpath work.
                once_decoded = urllib.parse.unquote(raw_input)
                representations.append(
                    os.path.normpath(os.path.abspath(os.path.expanduser(once_decoded)))
                )
            except Exception:
                pass
        for pattern in self.denied_patterns:
            if any(pattern.search(value) for value in representations):
                return True
        return False

    @staticmethod
    def _has_multiple_uri_encoding_layers(raw_input: str) -> bool:
        if "%" not in raw_input:
            return False
        once = urllib.parse.unquote(raw_input)
        return "%" in once and urllib.parse.unquote(once) != once

    def is_path_contained(self, target_path: str, root_path: str) -> bool:
        """Check whether target_path is strictly contained within root_path."""
        canonical_target = self.canonicalize_path(target_path)
        canonical_root = self.canonicalize_path(root_path)
        return self._is_canonical_path_contained(canonical_target, canonical_root)

    def _is_canonical_path_contained(self, canonical_target: str, canonical_root: str) -> bool:
        """Containment comparison over two already-canonical paths. Performs no
        canonicalization; callers must pass canonical inputs (e.g. the
        constructor-canonical roots and a target canonicalized once per call)."""
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

    def _validates_sensitive_path(self, canonical: str, raw_input: str) -> bool:
        """Use the base fast path unless a subclass or instance replaced the
        public security hook, in which case preserve its legacy authority."""
        method = self.is_sensitive_path
        if getattr(method, "__func__", None) is not SuretySandbox.is_sensitive_path:
            return method(raw_input) or method(canonical)
        return self._matches_denied_patterns(canonical, raw_input)

    def _validates_canonical_containment(
        self, canonical_target: str, canonical_root: str
    ) -> bool:
        method = self.is_path_contained
        if getattr(method, "__func__", None) is not SuretySandbox.is_path_contained:
            return method(canonical_target, canonical_root)
        return self._is_canonical_path_contained(canonical_target, canonical_root)

    def validate_path(
        self, target_path: str, is_write: bool = False
    ) -> Tuple[bool, str, bool, Optional[str]]:
        """
        Validate path against workspace boundaries, read-only constraints, and sensitive patterns.
        Returns: (allowed, normalized_path, is_read_only, reason)
        """
        if not target_path or not isinstance(target_path, str):
            return False, "", False, "Empty or invalid path provided."

        # Canonicalize exactly once per validation call; every stage below
        # reuses this value and the constructor-canonical roots instead of
        # re-resolving.
        canonical = self.canonicalize_path(target_path)

        # Traversal pattern check
        if ".." in target_path or "%2e%2e" in target_path.lower():
            if not any(
                self._validates_canonical_containment(canonical, root)
                for root in self.workspace_roots
            ):
                return (
                    False,
                    canonical,
                    False,
                    f'Path traversal detected: "{target_path}" resolves outside configured workspace roots.',
                )

        # 1. Check sensitive path deny-list (raw input + canonical form)
        if self._validates_sensitive_path(canonical, target_path):
            return (
                False,
                canonical,
                False,
                f'Access to sensitive path blocked by safety policy: "{target_path}".',
            )

        # A once-decoded path can name a different existing symlink/junction
        # than its fully decoded form. Reject that ambiguous class instead of
        # repeating filesystem resolution or weakening legacy checks.
        if self._has_multiple_uri_encoding_layers(target_path):
            return (
                False,
                canonical,
                False,
                f'Multi-layer URI encoding is not allowed in sandbox paths: "{target_path}".',
            )

        # 2. Check workspace containment
        if not any(
            self._validates_canonical_containment(canonical, root)
            for root in self.workspace_roots
        ):
            return (
                False,
                canonical,
                False,
                f'Path "{target_path}" is outside allowed workspace roots.',
            )

        # 3. Check read-only constraints
        is_read_only = any(
            self._validates_canonical_containment(canonical, ro_root)
            for ro_root in self.read_only_roots
        )

        if is_write and is_read_only:
            return (
                False,
                canonical,
                True,
                f'Write rejected: path "{target_path}" is located within a read-only root.',
            )

        return True, canonical, is_read_only, None
