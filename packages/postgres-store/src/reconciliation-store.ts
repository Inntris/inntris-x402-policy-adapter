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
  executionOperationId,
  type ExecutionOperationRecord,
  type ExecutionReconciliationStore,
  type ExecutionStartResult,
  type PrepareExecutionOperation,
} from "@inntris/execution-reconciliation";
import type { Pool, QueryResultRow } from "pg";

interface OperationRow extends QueryResultRow {
  operation_id: string;
  rail: string;
  operation_kind: string;
  decision_id: string;
  action_hash: string;
  execution_ref: string;
  binding_hash: string;
  status: string;
  attempt_count: number;
  prepared_at: Date | string;
  started_at: Date | string | null;
  updated_at: Date | string;
  resolved_at: Date | string | null;
  outcome_reference: string | null;
  last_error_code: string | null;
  resolved_by: string | null;
  resolution_note: string | null;
}

const SELECT_OPERATION = `
  SELECT operation_id, rail, operation_kind, decision_id, action_hash, execution_ref,
         binding_hash, status, attempt_count, prepared_at, started_at, updated_at,
         resolved_at, outcome_reference, last_error_code, resolved_by, resolution_note
  FROM inntris.execution_operations
`;

function iso(value: Date | string): string {
  return (value instanceof Date ? value : new Date(value)).toISOString();
}

function nullableIso(value: Date | string | null): string | null {
  return value === null ? null : iso(value);
}

function operationFromRow(row: OperationRow): ExecutionOperationRecord {
  return ExecutionOperationRecordSchema.parse({
    version: "inntris-execution-operation-v1",
    operationId: row.operation_id,
    rail: row.rail,
    operationKind: row.operation_kind,
    decisionId: row.decision_id,
    actionHash: row.action_hash,
    executionRef: row.execution_ref,
    bindingHash: row.binding_hash,
    status: row.status,
    attemptCount: row.attempt_count,
    preparedAt: iso(row.prepared_at),
    startedAt: nullableIso(row.started_at),
    updatedAt: iso(row.updated_at),
    resolvedAt: nullableIso(row.resolved_at),
    outcomeReference: row.outcome_reference,
    lastErrorCode: row.last_error_code,
    resolvedBy: row.resolved_by,
    resolutionNote: row.resolution_note,
  });
}

function operation(result: { rows: OperationRow[] }): ExecutionOperationRecord {
  const row = result.rows[0];
  if (row === undefined) {
    throw new ExecutionReconciliationError("Execution operation transition was rejected");
  }
  return operationFromRow(row);
}

function validateLimit(limit: number | undefined): number {
  const value = limit ?? 100;
  if (!Number.isInteger(value) || value < 1 || value > 500) {
    throw new TypeError("Reconciliation query limit must be an integer from 1 to 500");
  }
  return value;
}

export class PostgresExecutionReconciliationStore implements ExecutionReconciliationStore {
  constructor(readonly pool: Pool) {}

  async prepare(inputValue: PrepareExecutionOperation): Promise<ExecutionOperationRecord> {
    const input = PrepareExecutionOperationSchema.parse(inputValue);
    const operationId = executionOperationId(input);
    const result = await this.pool.query<OperationRow>(
      `
        INSERT INTO inntris.execution_operations (
          operation_id, rail, operation_kind, decision_id, action_hash,
          execution_ref, binding_hash, status, prepared_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, 'prepared', $8, $8)
        ON CONFLICT (operation_id) DO UPDATE
          SET operation_id = EXCLUDED.operation_id
          WHERE inntris.execution_operations.rail = EXCLUDED.rail
            AND inntris.execution_operations.operation_kind = EXCLUDED.operation_kind
            AND inntris.execution_operations.decision_id = EXCLUDED.decision_id
            AND inntris.execution_operations.action_hash = EXCLUDED.action_hash
            AND inntris.execution_operations.execution_ref = EXCLUDED.execution_ref
            AND inntris.execution_operations.binding_hash = EXCLUDED.binding_hash
        RETURNING *
      `,
      [
        operationId,
        input.rail,
        input.operationKind,
        input.decisionId,
        input.actionHash,
        input.executionRef,
        input.bindingHash,
        input.preparedAt,
      ],
    );
    if (result.rowCount !== 1) {
      throw new ExecutionReconciliationError(
        "Execution reference is already bound to a different operation",
      );
    }
    return operation(result);
  }

  async start(input: {
    operationId: string;
    bindingHash: string;
    startedAt: Date;
  }): Promise<ExecutionStartResult> {
    input = StartExecutionOperationSchema.parse(input);
    const claimed = await this.pool.query<OperationRow>(
      `
        UPDATE inntris.execution_operations
        SET status = 'in_progress', attempt_count = attempt_count + 1,
            started_at = $3, updated_at = $3
        WHERE operation_id = $1 AND binding_hash = $2 AND status = 'prepared'
        RETURNING *
      `,
      [input.operationId, input.bindingHash, input.startedAt],
    );
    if (claimed.rowCount === 1) {
      return { status: "claimed", operation: operation(claimed) };
    }
    const existing = await this.get(input.operationId);
    if (existing === undefined) return { status: "missing" };
    if (existing.bindingHash !== input.bindingHash) return { status: "conflict" };
    if (existing.status === "prepared") {
      throw new ExecutionReconciliationError("Execution operation could not be claimed");
    }
    return { status: existing.status, operation: existing };
  }

  async markSucceeded(input: {
    operationId: string;
    bindingHash: string;
    outcomeReference: string;
    resolvedAt: Date;
  }): Promise<ExecutionOperationRecord> {
    input = MarkExecutionSucceededSchema.parse(input);
    const result = await this.pool.query<OperationRow>(
      `
        UPDATE inntris.execution_operations
        SET status = 'succeeded', outcome_reference = $3,
            resolved_at = COALESCE(resolved_at, $4),
            updated_at = CASE WHEN status = 'in_progress' THEN $4 ELSE updated_at END
        WHERE operation_id = $1 AND binding_hash = $2
          AND (status = 'in_progress' OR (status = 'succeeded' AND outcome_reference = $3))
        RETURNING *
      `,
      [input.operationId, input.bindingHash, input.outcomeReference, input.resolvedAt],
    );
    return operation(result);
  }

  async markFailedFinal(input: {
    operationId: string;
    bindingHash: string;
    errorCode: string;
    resolvedAt: Date;
  }): Promise<ExecutionOperationRecord> {
    input = MarkExecutionFailedFinalSchema.parse(input);
    const result = await this.pool.query<OperationRow>(
      `
        UPDATE inntris.execution_operations
        SET status = 'failed_final', last_error_code = $3,
            resolved_at = COALESCE(resolved_at, $4),
            updated_at = CASE WHEN status = 'in_progress' THEN $4 ELSE updated_at END
        WHERE operation_id = $1 AND binding_hash = $2
          AND (status = 'in_progress' OR (status = 'failed_final' AND last_error_code = $3))
        RETURNING *
      `,
      [input.operationId, input.bindingHash, input.errorCode, input.resolvedAt],
    );
    return operation(result);
  }

  async markOutcomeUnknown(input: {
    operationId: string;
    bindingHash: string;
    errorCode: string;
    observedAt: Date;
  }): Promise<ExecutionOperationRecord> {
    input = MarkExecutionOutcomeUnknownSchema.parse(input);
    const result = await this.pool.query<OperationRow>(
      `
        UPDATE inntris.execution_operations
        SET status = 'outcome_unknown', last_error_code = COALESCE(last_error_code, $3),
            updated_at = CASE WHEN status = 'in_progress' THEN $4 ELSE updated_at END
        WHERE operation_id = $1 AND binding_hash = $2
          AND status IN ('in_progress', 'outcome_unknown')
        RETURNING *
      `,
      [input.operationId, input.bindingHash, input.errorCode, input.observedAt],
    );
    return operation(result);
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
    const result = await this.pool.query<OperationRow>(
      `
        UPDATE inntris.execution_operations
        SET status = $3, outcome_reference = $4,
            last_error_code = CASE WHEN $3 = 'failed_final' THEN $5 ELSE NULL END,
            resolved_by = $6, resolution_note = $7,
            resolved_at = $8, updated_at = $8
        WHERE operation_id = $1 AND binding_hash = $2
          AND status IN ('in_progress', 'outcome_unknown')
        RETURNING *
      `,
      [
        input.operationId,
        input.bindingHash,
        input.outcome,
        input.outcomeReference,
        input.errorCode ?? null,
        input.resolvedBy,
        input.resolutionNote,
        input.resolvedAt,
      ],
    );
    return operation(result);
  }

  async get(operationId: string): Promise<ExecutionOperationRecord | undefined> {
    const result = await this.pool.query<OperationRow>(
      `${SELECT_OPERATION} WHERE operation_id = $1`,
      [operationId],
    );
    const row = result.rows[0];
    return row === undefined ? undefined : operationFromRow(row);
  }

  async listUnresolved(
    input: { updatedBefore?: Date | undefined; limit?: number | undefined } = {},
  ): Promise<ExecutionOperationRecord[]> {
    input = ListUnresolvedExecutionOperationsSchema.parse(input);
    const result = await this.pool.query<OperationRow>(
      `
        ${SELECT_OPERATION}
        WHERE status IN ('in_progress', 'outcome_unknown')
          AND updated_at < $1
        ORDER BY updated_at, operation_id
        LIMIT $2
      `,
      [input.updatedBefore ?? new Date("9999-12-31T23:59:59.999Z"), validateLimit(input.limit)],
    );
    return result.rows.map(operationFromRow);
  }
}
