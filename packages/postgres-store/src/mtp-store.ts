import {
  MtpSignedVerifyRequestSchema,
  type MtpAuthorizationRecord,
  type MtpAuthorityStateStore,
  type MtpConsumptionReceipt,
  type MtpExecutionClaim,
} from "@inntris/mtp-authority";
import type { Pool, QueryResultRow } from "pg";

interface MtpAuthorizationRow extends QueryResultRow {
  decision_id: string;
  action_hash: string;
  verify_request: unknown;
  mtp_action_hash: string;
  approval_token: string;
  authorization_audit_id: string;
  authorized_at: Date | string;
  execution_ref: string | null;
  consumption_audit_id: string | null;
  consumption_status: "consumed" | "idempotent" | null;
  completed_at: Date | string | null;
}

function iso(value: Date | string): string {
  return (value instanceof Date ? value : new Date(value)).toISOString();
}

function isUniqueViolation(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "23505";
}

function recordFromRow(row: MtpAuthorizationRow): MtpAuthorizationRecord {
  return {
    decisionId: row.decision_id,
    actionHash: row.action_hash,
    request: MtpSignedVerifyRequestSchema.parse(row.verify_request),
    mtpActionHash: row.mtp_action_hash,
    approvalToken: row.approval_token,
    authorizationAuditId: row.authorization_audit_id,
    authorizedAt: iso(row.authorized_at),
    ...(row.execution_ref === null ? {} : { executionRef: row.execution_ref }),
    ...(row.consumption_audit_id === null ? {} : { consumptionAuditId: row.consumption_audit_id }),
    ...(row.consumption_status === null ? {} : { consumptionStatus: row.consumption_status }),
    ...(row.completed_at === null ? {} : { completedAt: iso(row.completed_at) }),
  };
}

export class PostgresMtpAuthorityStateStore implements MtpAuthorityStateStore {
  constructor(readonly pool: Pool) {}

  async saveAuthorization(record: MtpAuthorizationRecord): Promise<void> {
    const result = await this.pool.query(
      `
        INSERT INTO inntris.mtp_authorisations (
          decision_id, action_hash, mtp_agent_id, verify_request, mtp_action_hash,
          approval_token, authorization_audit_id, authorized_at
        ) VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, $8)
        ON CONFLICT (decision_id) DO UPDATE
          SET decision_id = EXCLUDED.decision_id
          WHERE inntris.mtp_authorisations.action_hash = EXCLUDED.action_hash
            AND inntris.mtp_authorisations.mtp_agent_id = EXCLUDED.mtp_agent_id
            AND inntris.mtp_authorisations.verify_request = EXCLUDED.verify_request
            AND inntris.mtp_authorisations.mtp_action_hash = EXCLUDED.mtp_action_hash
            AND inntris.mtp_authorisations.approval_token = EXCLUDED.approval_token
            AND inntris.mtp_authorisations.authorization_audit_id = EXCLUDED.authorization_audit_id
            AND inntris.mtp_authorisations.authorized_at = EXCLUDED.authorized_at
        RETURNING decision_id
      `,
      [
        record.decisionId,
        record.actionHash,
        record.request.agent_id,
        JSON.stringify(record.request),
        record.mtpActionHash,
        record.approvalToken,
        record.authorizationAuditId,
        record.authorizedAt,
      ],
    );
    if (result.rowCount !== 1) {
      throw new Error("MTP authorization state is immutable for a decision");
    }
  }

  async getAuthorization(decisionId: string): Promise<MtpAuthorizationRecord | undefined> {
    const result = await this.pool.query<MtpAuthorizationRow>(
      `
        SELECT decision_id, action_hash, verify_request, mtp_action_hash,
               approval_token, authorization_audit_id, authorized_at,
               execution_ref, consumption_audit_id, consumption_status, completed_at
        FROM inntris.mtp_authorisations
        WHERE decision_id = $1
      `,
      [decisionId],
    );
    const row = result.rows[0];
    return row === undefined ? undefined : recordFromRow(row);
  }

  async claimExecution(
    decisionId: string,
    actionHash: string,
    executionRef: string,
  ): Promise<MtpExecutionClaim> {
    let claimed: { rowCount: number | null };
    try {
      claimed = await this.pool.query(
        `
          UPDATE inntris.mtp_authorisations
          SET execution_ref = $3
          WHERE decision_id = $1 AND action_hash = $2 AND execution_ref IS NULL
          RETURNING decision_id
        `,
        [decisionId, actionHash, executionRef],
      );
    } catch (error) {
      if (isUniqueViolation(error)) return "conflict";
      throw error;
    }
    if (claimed.rowCount === 1) return "claimed";
    const existing = await this.pool.query<{
      action_hash: string;
      execution_ref: string | null;
    }>("SELECT action_hash, execution_ref FROM inntris.mtp_authorisations WHERE decision_id = $1", [
      decisionId,
    ]);
    const row = existing.rows[0];
    if (row === undefined) return "missing";
    return row.action_hash === actionHash && row.execution_ref === executionRef
      ? "idempotent"
      : "conflict";
  }

  async markMtpConsumed(
    decisionId: string,
    executionRef: string,
    receipt: MtpConsumptionReceipt,
  ): Promise<void> {
    if (receipt.executionRef !== executionRef) {
      throw new Error("MTP consumption receipt does not match the claimed execution");
    }
    const result = await this.pool.query(
      `
        UPDATE inntris.mtp_authorisations
        SET consumption_audit_id = COALESCE(consumption_audit_id, $3),
            consumption_status = COALESCE(consumption_status, $4)
        WHERE decision_id = $1
          AND execution_ref = $2
          AND (consumption_audit_id IS NULL OR consumption_audit_id = $3)
          AND (consumption_status IS NULL OR consumption_status = $4)
        RETURNING decision_id
      `,
      [decisionId, executionRef, receipt.consumptionAuditId, receipt.status],
    );
    if (result.rowCount !== 1) {
      throw new Error("MTP consumption receipt does not match the claimed execution");
    }
  }

  async markComplete(decisionId: string, executionRef: string, completedAt: string): Promise<void> {
    const result = await this.pool.query(
      `
        UPDATE inntris.mtp_authorisations
        SET completed_at = COALESCE(completed_at, $3)
        WHERE decision_id = $1
          AND execution_ref = $2
          AND consumption_audit_id IS NOT NULL
        RETURNING decision_id
      `,
      [decisionId, executionRef, completedAt],
    );
    if (result.rowCount !== 1) {
      throw new Error("MTP execution cannot complete before authority consumption");
    }
  }
}
