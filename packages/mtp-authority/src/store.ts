import { canonicalise } from "@inntris/decision-core";

import type {
  MtpAuthorizationRecord,
  MtpAuthorityStateStore,
  MtpConsumptionReceipt,
  MtpExecutionClaim,
} from "./types.js";

function copyRecord(record: MtpAuthorizationRecord): MtpAuthorizationRecord {
  return structuredClone(record);
}

function immutableAuthorization(record: MtpAuthorizationRecord): unknown {
  const {
    executionRef: ignoredExecutionRef,
    consumptionAuditId: ignoredConsumptionAuditId,
    consumptionStatus: ignoredConsumptionStatus,
    completedAt: ignoredCompletedAt,
    ...immutable
  } = record;
  void ignoredExecutionRef;
  void ignoredConsumptionAuditId;
  void ignoredConsumptionStatus;
  void ignoredCompletedAt;
  return immutable;
}

export class InMemoryMtpAuthorityStateStore implements MtpAuthorityStateStore {
  readonly #records = new Map<string, MtpAuthorizationRecord>();

  async saveAuthorization(record: MtpAuthorizationRecord): Promise<void> {
    const existing = this.#records.get(record.decisionId);
    if (
      existing !== undefined &&
      canonicalise(immutableAuthorization(existing)) !==
        canonicalise(immutableAuthorization(record))
    ) {
      throw new Error("MTP authorization state is immutable for a decision");
    }
    this.#records.set(record.decisionId, copyRecord(existing ?? record));
  }

  async getAuthorization(decisionId: string): Promise<MtpAuthorizationRecord | undefined> {
    const record = this.#records.get(decisionId);
    return record === undefined ? undefined : copyRecord(record);
  }

  async claimExecution(
    decisionId: string,
    actionHash: string,
    executionRef: string,
  ): Promise<MtpExecutionClaim> {
    const record = this.#records.get(decisionId);
    if (record === undefined) return "missing";
    if (record.actionHash !== actionHash) return "conflict";
    if (record.executionRef === undefined) {
      const duplicate = [...this.#records.values()].some(
        (candidate) =>
          candidate.decisionId !== decisionId &&
          candidate.request.agent_id === record.request.agent_id &&
          candidate.executionRef === executionRef,
      );
      if (duplicate) return "conflict";
      record.executionRef = executionRef;
      return "claimed";
    }
    return record.executionRef === executionRef ? "idempotent" : "conflict";
  }

  async markMtpConsumed(
    decisionId: string,
    executionRef: string,
    receipt: MtpConsumptionReceipt,
  ): Promise<void> {
    const record = this.#records.get(decisionId);
    if (record?.executionRef !== executionRef || receipt.executionRef !== executionRef) {
      throw new Error("MTP consumption receipt does not match the claimed execution");
    }
    if (
      record.consumptionAuditId !== undefined &&
      record.consumptionAuditId !== receipt.consumptionAuditId
    ) {
      throw new Error("MTP consumption evidence is immutable");
    }
    record.consumptionAuditId = receipt.consumptionAuditId;
    record.consumptionStatus = receipt.status;
  }

  async markComplete(decisionId: string, executionRef: string, completedAt: string): Promise<void> {
    const record = this.#records.get(decisionId);
    if (record?.executionRef !== executionRef || record.consumptionAuditId === undefined) {
      throw new Error("MTP execution cannot complete before authority consumption");
    }
    record.completedAt ??= completedAt;
  }
}
