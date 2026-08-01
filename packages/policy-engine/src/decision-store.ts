import type { InntrisActionV1, InntrisDecisionV1 } from "@inntris/decision-core";

export interface StoredDecision {
  decision: InntrisDecisionV1;
  action: InntrisActionV1;
}

export type ApprovalClaimResult = "claimed" | "already_claimed";

/**
 * Persists issued decisions and provides an atomic approval claim operation.
 * A production implementation must share this store across every decision
 * provider instance and make `claimApproval` a compare-and-set transaction.
 */
export interface DecisionStateStore {
  save(record: StoredDecision): Promise<void>;
  get(decisionId: string): Promise<StoredDecision | undefined>;
  claimApproval(decisionId: string): Promise<ApprovalClaimResult>;
}

/**
 * Process-local reference store. The synchronous check-and-set inside
 * `claimApproval` prevents concurrent resolutions within one process.
 */
export class InMemoryDecisionStateStore implements DecisionStateStore {
  readonly #decisions = new Map<string, StoredDecision>();
  readonly #claimedApprovals = new Set<string>();

  async save(record: StoredDecision): Promise<void> {
    this.#decisions.set(record.decision.decision_id, record);
  }

  async get(decisionId: string): Promise<StoredDecision | undefined> {
    return this.#decisions.get(decisionId);
  }

  async claimApproval(decisionId: string): Promise<ApprovalClaimResult> {
    if (this.#claimedApprovals.has(decisionId)) {
      return "already_claimed";
    }
    this.#claimedApprovals.add(decisionId);
    return "claimed";
  }
}
