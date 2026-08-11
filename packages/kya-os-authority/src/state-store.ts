import { canonicalise } from "@inntris/decision-core";

import {
  KyaAuthorityRevalidationRecordSchema,
  KyaDecisionAuthorityRecordSchema,
  type KyaAuthorityRevalidationRecord,
  type KyaDecisionAuthorityRecord,
} from "./schemas.js";
import type { KyaAuthorityStateStore, KyaNonceStore } from "./types.js";

export class InMemoryKyaNonceStore implements KyaNonceStore {
  readonly durability = "memory" as const;
  readonly #nonces = new Map<string, Date>();

  async consume(input: {
    did: string;
    nonce: string;
    consumedAt: Date;
    expiresAt: Date;
  }): Promise<"consumed" | "replay"> {
    const key = `${input.did}\u0000${input.nonce}`;
    const existing = this.#nonces.get(key);
    if (existing !== undefined && existing.getTime() >= input.consumedAt.getTime()) {
      return "replay";
    }
    this.#nonces.set(key, new Date(input.expiresAt));
    return "consumed";
  }

  async purgeExpired(at: Date): Promise<number> {
    let removed = 0;
    for (const [key, expiresAt] of this.#nonces) {
      if (expiresAt.getTime() < at.getTime()) {
        this.#nonces.delete(key);
        removed += 1;
      }
    }
    return removed;
  }
}

export class InMemoryKyaAuthorityStateStore implements KyaAuthorityStateStore {
  readonly durability = "memory" as const;
  readonly #decisions = new Map<string, KyaDecisionAuthorityRecord>();
  readonly #revalidations: KyaAuthorityRevalidationRecord[] = [];

  async saveDecisionAuthority(record: KyaDecisionAuthorityRecord): Promise<void> {
    const parsed = KyaDecisionAuthorityRecordSchema.parse(record);
    const existing = this.#decisions.get(parsed.decision_id);
    if (existing !== undefined && canonicalise(existing) !== canonicalise(parsed)) {
      throw new Error("KYA decision authority records are immutable");
    }
    this.#decisions.set(parsed.decision_id, parsed);
  }

  async getDecisionAuthority(decisionId: string): Promise<KyaDecisionAuthorityRecord | undefined> {
    return this.#decisions.get(decisionId);
  }

  async appendRevalidation(record: KyaAuthorityRevalidationRecord): Promise<void> {
    const parsed = KyaAuthorityRevalidationRecordSchema.parse(record);
    if (
      parsed.kind === "consumption" &&
      parsed.status === "verified" &&
      parsed.execution_ref !== null
    ) {
      const existing = await this.getSuccessfulExecutionRevalidation({
        decisionId: parsed.decision_id,
        actionHash: parsed.action_hash,
        executionRef: parsed.execution_ref,
      });
      if (existing !== undefined) return;
    }
    this.#revalidations.push(parsed);
  }

  async getSuccessfulExecutionRevalidation(input: {
    decisionId: string;
    actionHash: string;
    executionRef: string;
  }): Promise<KyaAuthorityRevalidationRecord | undefined> {
    return this.#revalidations.find(
      (record) =>
        record.kind === "consumption" &&
        record.status === "verified" &&
        record.decision_id === input.decisionId &&
        record.action_hash === input.actionHash &&
        record.execution_ref === input.executionRef,
    );
  }
}
