import {
  InntrisActionV1Schema,
  InntrisDecisionV1Schema,
  type ConsumeDecisionResult,
} from "@inntris/decision-core";
import {
  toCanonicalAmount,
  type ApprovalClaimResult,
  type AtomicConsumptionInput,
  type AtomicPolicyStateStore,
  type RecordSpendInput,
  type StoredDecision,
} from "@inntris/policy-engine";
import { Decimal } from "decimal.js";
import type { Pool, PoolClient, QueryResultRow } from "pg";

interface DecisionRow extends QueryResultRow {
  decision: unknown;
  action: unknown;
}

interface ConsumptionRow extends QueryResultRow {
  decision_id: string;
  nonce: string;
  action_hash: string;
  execution_ref: string;
  consumed_at: Date | string;
}

interface AmountRow extends QueryResultRow {
  amount: string;
}

function decimal(value: string, field: string): Decimal {
  const parsed = new Decimal(value);
  if (!parsed.isFinite() || parsed.isNegative()) {
    throw new Error(`${field} must be a non-negative decimal string`);
  }
  return parsed;
}

function consumedAt(value: Date | string): string {
  return (value instanceof Date ? value : new Date(value)).toISOString();
}

async function rollback(client: PoolClient): Promise<void> {
  await client.query("ROLLBACK").catch(() => undefined);
}

/**
 * PostgreSQL is the source of truth for policy decisions and consumption.
 * The caller owns the supplied pool and remains responsible for closing it.
 */
export class PostgresPolicyStateStore implements AtomicPolicyStateStore {
  constructor(readonly pool: Pool) {}

  async save(record: StoredDecision): Promise<void> {
    const result = await this.pool.query(
      `
        INSERT INTO inntris.decisions (decision_id, decision, action)
        VALUES ($1, $2::jsonb, $3::jsonb)
        ON CONFLICT (decision_id) DO UPDATE
          SET decision_id = EXCLUDED.decision_id
          WHERE inntris.decisions.decision = EXCLUDED.decision
            AND inntris.decisions.action = EXCLUDED.action
        RETURNING decision_id
      `,
      [record.decision.decision_id, JSON.stringify(record.decision), JSON.stringify(record.action)],
    );
    if (result.rowCount !== 1) {
      throw new Error("A signed decision with this decision_id already exists and is immutable");
    }
  }

  async get(decisionId: string): Promise<StoredDecision | undefined> {
    const result = await this.pool.query<DecisionRow>(
      "SELECT decision, action FROM inntris.decisions WHERE decision_id = $1",
      [decisionId],
    );
    const row = result.rows[0];
    if (row === undefined) return undefined;
    return {
      decision: InntrisDecisionV1Schema.parse(row.decision),
      action: InntrisActionV1Schema.parse(row.action),
    };
  }

  async claimApproval(decisionId: string): Promise<ApprovalClaimResult> {
    const result = await this.pool.query(
      `
        INSERT INTO inntris.approval_claims (decision_id)
        SELECT decision_id FROM inntris.decisions WHERE decision_id = $1
        ON CONFLICT (decision_id) DO NOTHING
        RETURNING decision_id
      `,
      [decisionId],
    );
    return result.rowCount === 1 ? "claimed" : "already_claimed";
  }

  async getDailySpend(principalId: string, dayKey: string): Promise<string> {
    const result = await this.pool.query<AmountRow>(
      `
        SELECT amount::text AS amount
        FROM inntris.daily_spend
        WHERE principal_id = $1 AND day_key = $2
      `,
      [principalId, dayKey],
    );
    return toCanonicalAmount(new Decimal(result.rows[0]?.amount ?? "0"));
  }

  async recordSpend(input: RecordSpendInput): Promise<void> {
    const amount = decimal(input.amount, "amount");
    await this.pool.query(
      `
        INSERT INTO inntris.daily_spend (principal_id, day_key, amount)
        VALUES ($1, $2, $3::numeric)
        ON CONFLICT (principal_id, day_key) DO UPDATE
          SET amount = inntris.daily_spend.amount + EXCLUDED.amount,
              updated_at = now()
      `,
      [input.principalId, input.dayKey, amount.toString()],
    );
  }

  async consumeAndRecordSpend(input: AtomicConsumptionInput): Promise<ConsumeDecisionResult> {
    const amount = decimal(input.spend.amount, "spend amount");
    const dailyLimit = decimal(input.dailyLimit, "daily limit");
    if (input.consumption.consumedAt.getTime() >= input.consumption.expiresAt.getTime()) {
      return {
        success: false,
        status: "rejected",
        decision_id: input.consumption.decisionId,
        execution_ref: input.consumption.executionRef,
        reason_code: "DECISION_EXPIRED",
      };
    }
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const inserted = await client.query<ConsumptionRow>(
        `
          INSERT INTO inntris.consumptions (
            decision_id, nonce, action_hash, execution_ref, expires_at, consumed_at
          )
          VALUES ($1, $2, $3, $4, $5, $6)
          ON CONFLICT DO NOTHING
          RETURNING decision_id, nonce, action_hash, execution_ref, consumed_at
        `,
        [
          input.consumption.decisionId,
          input.consumption.nonce,
          input.consumption.actionHash,
          input.consumption.executionRef,
          input.consumption.expiresAt,
          input.consumption.consumedAt,
        ],
      );

      if (inserted.rowCount === 0) {
        const existing = await client.query<ConsumptionRow>(
          `
            SELECT decision_id, nonce, action_hash, execution_ref, consumed_at
            FROM inntris.consumptions
            WHERE decision_id = $1 OR nonce = $2
            ORDER BY decision_id = $1 DESC
            LIMIT 1
          `,
          [input.consumption.decisionId, input.consumption.nonce],
        );
        await client.query("COMMIT");
        const row = existing.rows[0];
        if (
          row?.decision_id === input.consumption.decisionId &&
          row.nonce === input.consumption.nonce &&
          row.action_hash === input.consumption.actionHash &&
          row.execution_ref === input.consumption.executionRef
        ) {
          return {
            success: true,
            status: "idempotent",
            decision_id: input.consumption.decisionId,
            execution_ref: input.consumption.executionRef,
            consumed_at: consumedAt(row.consumed_at),
          };
        }
        return {
          success: false,
          status: "conflict",
          decision_id: input.consumption.decisionId,
          execution_ref: input.consumption.executionRef,
          reason_code: "NONCE_ALREADY_CONSUMED",
        };
      }

      const spend = await client.query<AmountRow>(
        `
          INSERT INTO inntris.daily_spend (principal_id, day_key, amount, updated_at)
          SELECT $1, $2, $3::numeric, $5
          WHERE $3::numeric <= $4::numeric
          ON CONFLICT (principal_id, day_key) DO UPDATE
            SET amount = inntris.daily_spend.amount + EXCLUDED.amount,
                updated_at = EXCLUDED.updated_at
            WHERE inntris.daily_spend.amount + EXCLUDED.amount <= $4::numeric
          RETURNING amount::text AS amount
        `,
        [
          input.spend.principalId,
          input.spend.dayKey,
          amount.toString(),
          dailyLimit.toString(),
          input.consumption.consumedAt,
        ],
      );
      if (spend.rowCount === 0) {
        await rollback(client);
        return {
          success: false,
          status: "rejected",
          decision_id: input.consumption.decisionId,
          execution_ref: input.consumption.executionRef,
          reason_code: "DAILY_LIMIT_EXCEEDED",
        };
      }

      await client.query("COMMIT");
      return {
        success: true,
        status: "consumed",
        decision_id: input.consumption.decisionId,
        execution_ref: input.consumption.executionRef,
        consumed_at: input.consumption.consumedAt.toISOString(),
      };
    } catch (error) {
      await rollback(client);
      throw error;
    } finally {
      client.release();
    }
  }
}
