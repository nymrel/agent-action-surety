/**
 * Agent Action Surety - Filesystem Path Containment Sandbox
 * Prevents directory traversal, symlink escapes, and sensitive credential exfiltration.
 * Zero external dependencies.
 * Copyright (c) 2026 Nymrel / JalenBuilds LLC.
 */

import * as path from 'node:path';
import * as fs from 'node:fs';

export interface SandboxOptions {
  workspaceRoots: string[];
  readOnlyRoots?: string[];
  deniedPatterns?: string[];
  allowSymlinksOutsideRoot?: boolean;
}

export interface PathValidationResult {
  allowed: boolean;
  normalizedPath: string;
  isReadOnly: boolean;
  reason?: string;
}

export class SuretySandbox {
  private workspaceRoots: string[] = [];
  private readOnlyRoots: string[] = [];
  private deniedPatterns: RegExp[] = [];
  private isWindows: boolean = process.platform === 'win32';

  // Default sensitive credential & system paths to protect
  private static DEFAULT_SENSITIVE_PATTERNS = [
    /\.git[\/\\]config$/i,
    /\.git[\/\\]credentials$/i,
    /\.git[\/\\]hooks[\/\\]/i,
    /\.env(\.[a-zA-Z0-9_-]+)?$/i,
    /[\/\\]\.ssh([\/\\]|$)/i,
    /[\/\\]\.aws([\/\\]|$)/i,
    /[\/\\]\.gnupg([\/\\]|$)/i,
    /[\/\\]id_rsa([\/\\]|$)/i,
    /[\/\\]id_ed25519([\/\\]|$)/i,
    /(\/|\\)etc(\/|\\)(passwd|shadow|sudoers)$/i,
    /^[a-zA-Z]:[\/\\]windows[\/\\]system32/i,
  ];

  constructor(options?: Partial<SandboxOptions>) {
    const roots = options?.workspaceRoots && options.workspaceRoots.length > 0
      ? options.workspaceRoots
      : [process.cwd()];

    this.workspaceRoots = roots.map((r) => this.canonicalizePath(r));
    this.readOnlyRoots = (options?.readOnlyRoots || []).map((r) => this.canonicalizePath(r));

    const userPatterns = (options?.deniedPatterns || []).map((p) => new RegExp(p, 'i'));
    this.deniedPatterns = [...SuretySandbox.DEFAULT_SENSITIVE_PATTERNS, ...userPatterns];
  }

  /**
   * Canonicalize and normalize a path for secure comparison.
   */
  public canonicalizePath(targetPath: string): string {
    if (!targetPath || typeof targetPath !== 'string') {
      return '';
    }

    // Decode up to two URI-encoding layers. The previous validation flow
    // canonicalized the target again in downstream helpers, so retaining the
    // second decode here preserves double-encoded traversal protection while
    // doing filesystem resolution only once.
    let decoded = targetPath;
    for (let pass = 0; pass < 2 && decoded.includes('%'); pass += 1) {
      try {
        const next = decodeURIComponent(decoded);
        if (next === decoded) break;
        decoded = next;
      } catch {
        // Keep the last valid form if decoding fails.
        break;
      }
    }

    // Resolve absolute path
    const resolved = path.resolve(decoded);
    const normalized = path.normalize(resolved);

    // If file exists, attempt realpath to defeat symlink bypasses
    try {
      if (fs.existsSync(normalized)) {
        return fs.realpathSync(normalized);
      }
    } catch {
      // If path doesn't exist yet, resolve parent realpath if parent exists
      try {
        const parent = path.dirname(normalized);
        if (fs.existsSync(parent)) {
          const realParent = fs.realpathSync(parent);
          return path.join(realParent, path.basename(normalized));
        }
      } catch {
        // Fallback to normalized
      }
    }

    return normalized;
  }

  /**
   * Check if a path targets sensitive secrets or system resources.
   */
  public isSensitivePath(targetPath: string): boolean {
    const canonical = this.canonicalizePath(targetPath);
    return this.matchesDeniedPatterns(canonical, targetPath);
  }

  /**
   * Pattern-only sensitive check over an already-canonical path plus its raw
   * input. Callers must guarantee `canonical` is the canonical form of
   * `rawInput`; no filesystem work happens here.
   */
  private matchesDeniedPatterns(canonical: string, rawInput: string): boolean {
    const representations = [canonical, rawInput];
    if (rawInput.includes('%')) {
      try {
        // Preserve the once-decoded normalized form examined by the legacy
        // helper chain, without repeating exists/realpath filesystem work.
        representations.push(path.normalize(path.resolve(decodeURIComponent(rawInput))));
      } catch {
        // Malformed encoding remains represented by the raw input.
      }
    }
    for (const pattern of this.deniedPatterns) {
      if (representations.some((value) => pattern.test(value))) {
        return true;
      }
    }
    return false;
  }

  private hasMultipleUriEncodingLayers(rawInput: string): boolean {
    if (!rawInput.includes('%')) return false;
    try {
      const once = decodeURIComponent(rawInput);
      return once.includes('%') && decodeURIComponent(once) !== once;
    } catch {
      return false;
    }
  }

  /**
   * Check whether targetPath is contained within rootPath.
   */
  public isPathContained(targetPath: string, rootPath: string): boolean {
    const canonicalTarget = this.canonicalizePath(targetPath);
    const canonicalRoot = this.canonicalizePath(rootPath);
    return this.isCanonicalPathContained(canonicalTarget, canonicalRoot);
  }

  /**
   * Containment comparison over two already-canonical paths. Performs no
   * canonicalization; callers must pass canonical inputs (e.g. the
   * constructor-canonical roots and a target canonicalized once per call).
   */
  private isCanonicalPathContained(canonicalTarget: string, canonicalRoot: string): boolean {
    if (this.isWindows) {
      const targetLower = canonicalTarget.toLowerCase();
      const rootLower = canonicalRoot.toLowerCase();

      if (targetLower === rootLower) return true;
      const relative = path.relative(rootLower, targetLower);
      return !relative.startsWith('..') && !path.isAbsolute(relative);
    } else {
      if (canonicalTarget === canonicalRoot) return true;
      const relative = path.relative(canonicalRoot, canonicalTarget);
      return !relative.startsWith('..') && !path.isAbsolute(relative);
    }
  }

  /** Preserve subclass/instance policy overrides while keeping the base class
   * on the single-canonicalization fast path. */
  private validatesSensitivePath(canonical: string, rawInput: string): boolean {
    if (this.isSensitivePath !== SuretySandbox.prototype.isSensitivePath) {
      return this.isSensitivePath(rawInput) || this.isSensitivePath(canonical);
    }
    return this.matchesDeniedPatterns(canonical, rawInput);
  }

  private validatesCanonicalContainment(canonicalTarget: string, canonicalRoot: string): boolean {
    if (this.isPathContained !== SuretySandbox.prototype.isPathContained) {
      return this.isPathContained(canonicalTarget, canonicalRoot);
    }
    return this.isCanonicalPathContained(canonicalTarget, canonicalRoot);
  }

  /**
   * Validate path against workspace boundaries, read-only constraints, and sensitive patterns.
   */
  public validatePath(targetPath: string, isWrite: boolean = false): PathValidationResult {
    if (!targetPath || typeof targetPath !== 'string') {
      return {
        allowed: false,
        normalizedPath: '',
        isReadOnly: false,
        reason: 'Empty or invalid path provided.',
      };
    }

    // Canonicalize exactly once per validation call; every stage below reuses
    // this value and the constructor-canonical roots instead of re-resolving.
    const canonical = this.canonicalizePath(targetPath);

    // Traversal pattern check on raw input
    if (targetPath.includes('..') || targetPath.includes('%2e%2e')) {
      let isInsideAnyRoot = false;
      for (const root of this.workspaceRoots) {
        if (this.validatesCanonicalContainment(canonical, root)) {
          isInsideAnyRoot = true;
          break;
        }
      }
      if (!isInsideAnyRoot) {
        return {
          allowed: false,
          normalizedPath: canonical,
          isReadOnly: false,
          reason: `Path traversal detected: "${targetPath}" resolves outside configured workspace roots.`,
        };
      }
    }

    // 1. Check sensitive path deny-list (raw input + canonical form)
    if (this.validatesSensitivePath(canonical, targetPath)) {
      return {
        allowed: false,
        normalizedPath: canonical,
        isReadOnly: false,
        reason: `Access to sensitive path blocked by safety policy: "${targetPath}".`,
      };
    }

    // A once-decoded path can name a different existing symlink/junction than
    // its fully decoded form. Reject the ambiguous class instead of performing
    // a second filesystem resolution or silently weakening legacy checks.
    if (this.hasMultipleUriEncodingLayers(targetPath)) {
      return {
        allowed: false,
        normalizedPath: canonical,
        isReadOnly: false,
        reason: `Multi-layer URI encoding is not allowed in sandbox paths: "${targetPath}".`,
      };
    }

    // 2. Check workspace containment
    let isContained = false;
    for (const root of this.workspaceRoots) {
      if (this.validatesCanonicalContainment(canonical, root)) {
        isContained = true;
        break;
      }
    }

    if (!isContained) {
      return {
        allowed: false,
        normalizedPath: canonical,
        isReadOnly: false,
        reason: `Path "${targetPath}" is outside allowed workspace roots.`,
      };
    }

    // 3. Check read-only constraints
    let isReadOnly = false;
    for (const roRoot of this.readOnlyRoots) {
      if (this.validatesCanonicalContainment(canonical, roRoot)) {
        isReadOnly = true;
        break;
      }
    }

    if (isWrite && isReadOnly) {
      return {
        allowed: false,
        normalizedPath: canonical,
        isReadOnly: true,
        reason: `Write rejected: path "${targetPath}" is located within a read-only root.`,
      };
    }

    return {
      allowed: true,
      normalizedPath: canonical,
      isReadOnly,
    };
  }
}
