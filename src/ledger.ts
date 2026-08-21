/**
 * Agent Action Surety - Cryptographic Audit Ledger & Receipt Generator
 * Generates tamper-evident SHA-256 Merkle-linked action receipts.
 * Zero external dependencies.
 * Copyright (c) 2026 Nymrel / JalenBuilds LLC.
 */

import * as crypto from 'node:crypto';
import { ActionReceipt, ActionEnvelope, PolicyEvaluationResult, ActionType, PolicyDecision } from './types.js';

export class ExecutionLedger {
  private sessionId: string;
  private hmacSecret?: string;
  private receiptHistory: ActionReceipt[] = [];
  private lastReceiptHash: string;

  public static GENESIS_PREV_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

  constructor(options?: { sessionId?: string; hmacSecret?: string }) {
    this.sessionId = options?.sessionId || `session_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    this.hmacSecret = options?.hmacSecret;
    this.lastReceiptHash = ExecutionLedger.GENESIS_PREV_HASH;
  }

  public getSessionId(): string {
    return this.sessionId;
  }

  public getHistory(): ReadonlyArray<ActionReceipt> {
    return this.receiptHistory;
  }

  /**
   * Deterministically canonicalize action data into a stable JSON string for hashing.
   */
  public static canonicalizeData(data: Record<string, unknown>): string {
    const keys = Object.keys(data).sort();
    const sortedObj: Record<string, unknown> = {};
    for (const key of keys) {
      const val = data[key];
      if (val !== undefined) {
        sortedObj[key] = val;
      }
    }
    return JSON.stringify(sortedObj);
  }

  /**
   * Compute SHA-256 hash of a string.
   */
  public static sha256(content: string): string {
    return crypto.createHash('sha256').update(content, 'utf8').digest('hex');
  }

  /**
   * Compute HMAC-SHA256 signature if secret is provided.
   */
  public static hmacSha256(content: string, secret: string): string {
    return crypto.createHmac('sha256', secret).update(content, 'utf8').digest('hex');
  }

  /**
   * Record a policy evaluation and emit a cryptographically linked ActionReceipt.
   */
  public recordAction(
    action: ActionEnvelope,
    evaluation: PolicyEvaluationResult
  ): ActionReceipt {
    const timestamp = evaluation.timestamp || Date.now();
    const receiptId = `rcpt_${timestamp}_${crypto.randomBytes(4).toString('hex')}`;
    const actionId = action.id || `act_${timestamp}_${crypto.randomBytes(3).toString('hex')}`;

    const prevReceiptHash = this.lastReceiptHash;

    const payloadToHash: Record<string, unknown> = {
      actionId,
      actionType: action.actionType,
      commandSummary: action.command ? action.command.slice(0, 160) : undefined,
      decision: evaluation.decision,
      metadata: action.metadata || {},
      prevReceiptHash,
      receiptId,
      sessionId: this.sessionId,
      targetPath: action.targetPath,
      timestamp,
      violationsCount: evaluation.violations.length,
    };

    const canonicalString = ExecutionLedger.canonicalizeData(payloadToHash);
    const receiptHash = ExecutionLedger.sha256(canonicalString);

    let signature: string | undefined;
    if (this.hmacSecret) {
      signature = ExecutionLedger.hmacSha256(receiptHash, this.hmacSecret);
    }

    const receipt: ActionReceipt = {
      receiptId,
      sessionId: this.sessionId,
      actionId,
      actionType: action.actionType,
      decision: evaluation.decision,
      commandSummary: action.command ? action.command.slice(0, 160) : undefined,
      targetPath: action.targetPath,
      violationsCount: evaluation.violations.length,
      prevReceiptHash,
      receiptHash,
      signature,
      timestamp,
      metadata: {
        ...action.metadata,
        parentOrganization: 'Nymrel -> JalenBuilds LLC',
        verifiableTrust: true,
      },
    };

    this.receiptHistory.push(receipt);
    this.lastReceiptHash = receiptHash;

    return receipt;
  }

  /**
   * Verify integrity of a single receipt against its hash and HMAC signature.
   */
  public static verifyReceipt(receipt: ActionReceipt, hmacSecret?: string): boolean {
    const payloadToHash: Record<string, unknown> = {
      actionId: receipt.actionId,
      actionType: receipt.actionType,
      commandSummary: receipt.commandSummary,
      decision: receipt.decision,
      metadata: receipt.metadata || {},
      prevReceiptHash: receipt.prevReceiptHash,
      receiptId: receipt.receiptId,
      sessionId: receipt.sessionId,
      targetPath: receipt.targetPath,
      timestamp: receipt.timestamp,
      violationsCount: receipt.violationsCount,
    };

    const canonicalString = ExecutionLedger.canonicalizeData(payloadToHash);
    const expectedHash = ExecutionLedger.sha256(canonicalString);

    if (receipt.receiptHash !== expectedHash) {
      return false;
    }

    if (hmacSecret) {
      if (!receipt.signature) {
        return false;
      }
      const expectedSig = ExecutionLedger.hmacSha256(expectedHash, hmacSecret);
      if (receipt.signature !== expectedSig) {
        return false;
      }
    }

    return true;
  }

  /**
   * Verify the entire chain of receipts for tamper-evidence.
   */
  public static verifyChain(
    receipts: ActionReceipt[],
    hmacSecret?: string
  ): { valid: boolean; brokenIndex?: number; reason?: string } {
    if (!receipts || receipts.length === 0) {
      return { valid: true };
    }

    let expectedPrevHash = ExecutionLedger.GENESIS_PREV_HASH;

    for (let i = 0; i < receipts.length; i++) {
      const receipt = receipts[i];

      // Check chaining link
      if (receipt.prevReceiptHash !== expectedPrevHash) {
        return {
          valid: false,
          brokenIndex: i,
          reason: `Chain broken at index ${i}: prevReceiptHash does not match previous hash.`,
        };
      }

      // Check receipt self-integrity
      if (!ExecutionLedger.verifyReceipt(receipt, hmacSecret)) {
        return {
          valid: false,
          brokenIndex: i,
          reason: `Receipt integrity verification failed at index ${i}.`,
        };
      }

      expectedPrevHash = receipt.receiptHash;
    }

    return { valid: true };
  }

  /**
   * Export all recorded receipts formatted as JSON Lines.
   */
  public exportJsonl(): string {
    return this.receiptHistory.map((r) => JSON.stringify(r)).join('\n');
  }
}
