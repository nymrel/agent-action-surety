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

    // Decode URI encoding if present (e.g. %2e%2e%2f)
    let decoded = targetPath;
    try {
      if (decoded.includes('%')) {
        decoded = decodeURIComponent(decoded);
      }
    } catch {
      // Keep original if decoding fails
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
    for (const pattern of this.deniedPatterns) {
      if (pattern.test(canonical) || pattern.test(targetPath)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Check whether targetPath is contained within rootPath.
   */
  public isPathContained(targetPath: string, rootPath: string): boolean {
    const canonicalTarget = this.canonicalizePath(targetPath);
    const canonicalRoot = this.canonicalizePath(rootPath);

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

    // Traversal pattern check on raw input
    if (targetPath.includes('..') || targetPath.includes('%2e%2e')) {
      const canonical = this.canonicalizePath(targetPath);
      let isInsideAnyRoot = false;
      for (const root of this.workspaceRoots) {
        if (this.isPathContained(canonical, root)) {
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

    const canonical = this.canonicalizePath(targetPath);

    // 1. Check sensitive path deny-list
    if (this.isSensitivePath(targetPath) || this.isSensitivePath(canonical)) {
      return {
        allowed: false,
        normalizedPath: canonical,
        isReadOnly: false,
        reason: `Access to sensitive path blocked by safety policy: "${targetPath}".`,
      };
    }

    // 2. Check workspace containment
    let isContained = false;
    for (const root of this.workspaceRoots) {
      if (this.isPathContained(canonical, root)) {
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
      if (this.isPathContained(canonical, roRoot)) {
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
