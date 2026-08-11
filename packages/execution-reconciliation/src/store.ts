import { hashCanonical } from "@inntris/decision-core";

import {
  ExecutionOperationRecordSchema,
  ExecutionReconciliationError,
  ListUnresolvedExecutionOperationsSchema,
  MarkExecutionFailedFinalSchema,
  MarkExecutionOutcomeUnknownSchema,
  MarkExecutionSucceededSchema,
  PrepareExecutionOperationSchema,
  ResolveExecutionOperationSchema,
  StartExecutionOperationSchema,
  type ExecutionOperationRecord,
  type ExecutionReconciliationStore,
  type ExecutionStartResult,
  type PrepareExecutionOperation,
} from "./types.js";

export function executionOperationId(
  input: Pick<PrepareExecutionOperation, "rail" | "operationKind" | "executionRef">,
): string {
  return hashCanonical({
    version: "inntris-execution-operation-id-v1",
    rail: input.rail,
    operation_kind: input.operationKind,
    execution_ref: input.executionRef,
  });
}

function copy(record: ExecutionOperationRecord): ExecutionOperationRecord {
  return structuredClone(record);
}

function validatedCopy(record: ExecutionOperationRecord): ExecutionOperationRecord {
  return ExecutionOperationRecordSchema.parse(copy(record));
}

function sameIdentity(record: ExecutionOperationRecord, input: PrepareExecutionOperation): boolean {
  return (
    record.rail === input.rail &&
    record.operationKind === input.operationKind &&
    record.decisionId === input.decisionId &&
    record.actionHash === input.actionHash &&
    record.executionRef === input.executionRef &&
    record.bindingHash === input.bindingHash
  );
}

function assertMutation(
  record: ExecutionOperationRecord | undefined,
  bindingHash: string,
): ExecutionOperationRecord {
  if (record === undefined) {
    throw new ExecutionReconciliationError("Execution operation does not exist");
  }
  if (record.bindingHash !== bindingHash) {
    throw new ExecutionReconciliationError("Execution operation binding conflicts");
  }
  return record;
}

function validateLimit(limit: number | undefined): number {
  const value = limit ?? 100;
  if (!Number.isInteger(value) || value < 1 || value > 500) {
    throw new TypeError("Reconciliation query limit must be an integer from 1 to 500");
  }
  return value;
}

export class InMemoryExecutionReconciliationStore implements ExecutionReconciliationStore {
  readonly #operations = new Map<string, ExecutionOperationRecord>();

  async prepare(inputValue: PrepareExecutionOperation): Promise<ExecutionOperationRecord> {
    const input = PrepareExecutionOperationSchema.parse(inputValue);
    const operationId = executionOperationId(input);
    const existing = this.#operations.get(operationId);
    if (existing !== undefined) {
      if (!sameIdentity(existing, input)) {
        throw new ExecutionReconciliationError(
          "Execution reference is already bound to a different operation",
        );
      }
      return copy(existing);
    }
    const preparedAt = input.preparedAt.toISOString();
    const record = ExecutionOperationRecordSchema.parse({
      version: "inntris-execution-operation-v1",
      operationId,
      rail: input.rail,
      operationKind: input.operationKind,
      decisionId: input.decisionId,
      actionHash: input.actionHash,
      executionRef: input.executionRef,
      bindingHash: input.bindingHash,
      status: "prepared",
      attemptCount: 0,
      preparedAt,
      startedAt: null,
      updatedAt: preparedAt,
      resolvedAt: null,
      outcomeReference: null,
      lastErrorCode: null,
      resolvedBy: null,
      resolutionNote: null,
    });
    this.#operations.set(operationId, record);
    return copy(record);
  }

  async start(input: {
    operationId: string;
    bindingHash: string;
    startedAt: Date;
  }): Promise<ExecutionStartResult> {
    input = StartExecutionOperationSchema.parse(input);
    const record = this.#operations.get(input.operationId);
    if (record === undefined) return { status: "missing" };
    if (record.bindingHash !== input.bindingHash) return { status: "conflict" };
    if (record.status === "prepared") {
      const startedAt = input.startedAt.toISOString();
      record.status = "in_progress";
      record.attemptCount += 1;
      record.startedAt = startedAt;
      record.updatedAt = startedAt;
      return { status: "claimed", operation: copy(record) };
    }
    return { status: record.status, operation: copy(record) };
  }

  async markSucceeded(input: {
    operationId: string;
    bindingHash: string;
    outcomeReference: string;
    resolvedAt: Date;
  }): Promise<ExecutionOperationRecord> {
    input = MarkExecutionSucceededSchema.parse(input);
    const record = assertMutation(this.#operations.get(input.operationId), input.bindingHash);
    if (record.status === "succeeded" && record.outcomeReference === input.outcomeReference) {
      return copy(record);
    }
    if (record.status !== "in_progress") {
      throw new ExecutionReconciliationError("Only an in-progress operation can succeed normally");
    }
    const resolvedAt = input.resolvedAt.toISOString();
    record.status = "succeeded";
    record.outcomeReference = input.outcomeReference;
    record.resolvedAt = resolvedAt;
    record.updatedAt = resolvedAt;
    return validatedCopy(record);
  }

  async markFailedFinal(input: {
    operationId: string;
    bindingHash: string;
    errorCode: string;
    resolvedAt: Date;
  }): Promise<ExecutionOperationRecord> {
    input = MarkExecutionFailedFinalSchema.parse(input);
    const record = assertMutation(this.#operations.get(input.operationId), input.bindingHash);
    if (record.status === "failed_final" && record.lastErrorCode === input.errorCode) {
      return copy(record);
    }
    if (record.status !== "in_progress") {
      throw new ExecutionReconciliationError(
        "Only an in-progress operation can fail finally without reconciliation",
      );
    }
    const resolvedAt = input.resolvedAt.toISOString();
    record.status = "failed_final";
    record.lastErrorCode = input.errorCode;
    record.resolvedAt = resolvedAt;
    record.updatedAt = resolvedAt;
    return validatedCopy(record);
  }

  async markOutcomeUnknown(input: {
    operationId: string;
    bindingHash: string;
    errorCode: string;
    observedAt: Date;
  }): Promise<ExecutionOperationRecord> {
    input = MarkExecutionOutcomeUnknownSchema.parse(input);
    const record = assertMutation(this.#operations.get(input.operationId), input.bindingHash);
    if (record.status === "outcome_unknown") return copy(record);
    if (record.status !== "in_progress") {
      throw new ExecutionReconciliationError(
        "Only an in-progress operation can become outcome-unknown",
      );
    }
    const observedAt = input.observedAt.toISOString();
    record.status = "outcome_unknown";
    record.lastErrorCode = input.errorCode;
    record.updatedAt = observedAt;
    return validatedCopy(record);
  }

  async resolve(input: {
    operationId: string;
    bindingHash: string;
    outcome: "succeeded" | "failed_final";
    outcomeReference: string;
    errorCode?: string | undefined;
    resolvedBy: string;
    resolutionNote: string;
    resolvedAt: Date;
  }): Promise<ExecutionOperationRecord> {
    input = ResolveExecutionOperationSchema.parse(input);
    const record = assertMutation(this.#operations.get(input.operationId), input.bindingHash);
    if (record.status !== "outcome_unknown" && record.status !== "in_progress") {
      throw new ExecutionReconciliationError(
        "Only an unresolved operation can receive an authoritative resolution",
      );
    }
    const resolvedAt = input.resolvedAt.toISOString();
    record.status = input.outcome;
    record.outcomeReference = input.outcomeReference;
    record.lastErrorCode = input.outcome === "failed_final" ? (input.errorCode ?? null) : null;
    record.resolvedBy = input.resolvedBy;
    record.resolutionNote = input.resolutionNote;
    record.resolvedAt = resolvedAt;
    record.updatedAt = resolvedAt;
    return ExecutionOperationRecordSchema.parse(copy(record));
  }

  async get(operationId: string): Promise<ExecutionOperationRecord | undefined> {
    const record = this.#operations.get(operationId);
    return record === undefined ? undefined : copy(record);
  }

  async listUnresolved(
    input: { updatedBefore?: Date | undefined; limit?: number | undefined } = {},
  ): Promise<ExecutionOperationRecord[]> {
    input = ListUnresolvedExecutionOperationsSchema.parse(input);
    const limit = validateLimit(input.limit);
    const before = input.updatedBefore?.getTime() ?? Number.POSITIVE_INFINITY;
    return [...this.#operations.values()]
      .filter(
        (operation) =>
          (operation.status === "in_progress" || operation.status === "outcome_unknown") &&
          Date.parse(operation.updatedAt) < before,
      )
      .sort((left, right) => left.updatedAt.localeCompare(right.updatedAt))
      .slice(0, limit)
      .map(copy);
  }
}
