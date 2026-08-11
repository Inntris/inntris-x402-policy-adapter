import {
  KyaAuthorityRevalidationRecordSchema,
  KyaDecisionAuthorityRecordSchema,
  type KyaAuthorityRevalidationRecord,
  type KyaAuthorityStateStore,
  type KyaDecisionAuthorityRecord,
  type KyaNonceStore,
} from "@inntris/kya-os-authority";
import { hashCanonical } from "@inntris/decision-core";
import type { Pool, QueryResultRow } from "pg";

interface DecisionAuthorityRow extends QueryResultRow {
  decision_id: string;
  action_hash: string;
  action_json: unknown;
  binding_json: unknown;
  created_at: Date | string;
}

interface RevalidationRow extends QueryResultRow {
  id: string;
  decision_id: string;
  action_hash: string;
  kind: "approval" | "consumption";
  execution_ref: string | null;
  approval_reference: string | null;
  presentation_hash: string;
  authority_hash: string | null;
  status: "verified" | "rejected";
  reason_code: string | null;
  verified_at: Date | string;
}

function iso(value: Date | string): string {
  return (value instanceof Date ? value : new Date(value)).toISOString();
}

export class PostgresKyaNonceStore implements KyaNonceStore {
  readonly durability = "durable" as const;

  constructor(readonly pool: Pool) {}

  async consume(input: {
    did: string;
    nonce: string;
    consumedAt: Date;
    expiresAt: Date;
  }): Promise<"consumed" | "replay"> {
    const result = await this.pool.query(
      `
        INSERT INTO inntris.kya_proof_nonces (did, nonce, consumed_at, expires_at)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (did, nonce) DO UPDATE
          SET consumed_at = EXCLUDED.consumed_at,
              expires_at = EXCLUDED.expires_at
          WHERE inntris.kya_proof_nonces.expires_at < EXCLUDED.consumed_at
        RETURNING did
      `,
      [input.did, input.nonce, input.consumedAt, input.expiresAt],
    );
    return result.rowCount === 1 ? "consumed" : "replay";
  }

  async purgeExpired(at: Date): Promise<number> {
    const result = await this.pool.query(
      "DELETE FROM inntris.kya_proof_nonces WHERE expires_at < $1",
      [at],
    );
    return result.rowCount ?? 0;
  }
}

export class PostgresKyaAuthorityStateStore implements KyaAuthorityStateStore {
  readonly durability = "durable" as const;

  constructor(readonly pool: Pool) {}

  async saveDecisionAuthority(record: KyaDecisionAuthorityRecord): Promise<void> {
    const parsed = KyaDecisionAuthorityRecordSchema.parse(record);
    const result = await this.pool.query(
      `
        INSERT INTO inntris.kya_authority_decisions (
          decision_id, action_hash, action_json, binding_json, authority_hash,
          authority_policy_hash, presentation_hash, proof_hash,
          delegation_chain_hash, agent_did, responsible_party_did,
          authority_expires_at, created_at
        )
        VALUES ($1, $2, $3::jsonb, $4::jsonb, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        ON CONFLICT (decision_id) DO NOTHING
        RETURNING decision_id
      `,
      [
        parsed.decision_id,
        parsed.action_hash,
        JSON.stringify(parsed.action),
        JSON.stringify(parsed.binding),
        parsed.binding.authority_hash,
        parsed.binding.authority_policy_hash,
        parsed.binding.presentation_hash,
        parsed.binding.proof_hash,
        parsed.binding.delegation_chain_hash,
        parsed.binding.agent_did,
        parsed.binding.responsible_party_did,
        parsed.binding.authority_expires_at,
        parsed.created_at,
      ],
    );
    if (result.rowCount === 1) return;
    const existing = await this.getDecisionAuthority(parsed.decision_id);
    if (existing !== undefined && hashCanonical(existing) === hashCanonical(parsed)) return;
    throw new Error("A KYA decision authority record with this id already exists and is immutable");
  }

  async getDecisionAuthority(decisionId: string): Promise<KyaDecisionAuthorityRecord | undefined> {
    const result = await this.pool.query<DecisionAuthorityRow>(
      `
        SELECT decision_id, action_hash, action_json, binding_json, created_at
        FROM inntris.kya_authority_decisions
        WHERE decision_id = $1
      `,
      [decisionId],
    );
    const row = result.rows[0];
    if (row === undefined) return undefined;
    return KyaDecisionAuthorityRecordSchema.parse({
      decision_id: row.decision_id,
      action_hash: row.action_hash,
      action: row.action_json,
      binding: row.binding_json,
      created_at: iso(row.created_at),
    });
  }

  async appendRevalidation(record: KyaAuthorityRevalidationRecord): Promise<void> {
    const parsed = KyaAuthorityRevalidationRecordSchema.parse(record);
    await this.pool.query(
      `
        INSERT INTO inntris.kya_authority_revalidations (
          id, decision_id, action_hash, kind, execution_ref, approval_reference,
          presentation_hash, authority_hash, status, reason_code, verified_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        ON CONFLICT (decision_id, action_hash, execution_ref, kind)
          WHERE kind = 'consumption' AND status = 'verified'
        DO NOTHING
      `,
      [
        parsed.id,
        parsed.decision_id,
        parsed.action_hash,
        parsed.kind,
        parsed.execution_ref,
        parsed.approval_reference,
        parsed.presentation_hash,
        parsed.authority_hash,
        parsed.status,
        parsed.reason_code,
        parsed.verified_at,
      ],
    );
  }

  async getSuccessfulExecutionRevalidation(input: {
    decisionId: string;
    actionHash: string;
    executionRef: string;
  }): Promise<KyaAuthorityRevalidationRecord | undefined> {
    const result = await this.pool.query<RevalidationRow>(
      `
        SELECT id, decision_id, action_hash, kind, execution_ref, approval_reference,
               presentation_hash, authority_hash, status, reason_code, verified_at
        FROM inntris.kya_authority_revalidations
        WHERE decision_id = $1
          AND action_hash = $2
          AND execution_ref = $3
          AND kind = 'consumption'
          AND status = 'verified'
        LIMIT 1
      `,
      [input.decisionId, input.actionHash, input.executionRef],
    );
    const row = result.rows[0];
    if (row === undefined) return undefined;
    return KyaAuthorityRevalidationRecordSchema.parse({
      ...row,
      verified_at: iso(row.verified_at),
    });
  }
}
