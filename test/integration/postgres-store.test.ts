import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { createPublicDemoSigner } from "@inntris/decision-core";
import { LocalPolicyDecisionProvider, parsePolicyText } from "@inntris/policy-engine";
import { migratePostgresStore, PostgresPolicyStateStore } from "@inntris/postgres-store";
import { actionFromX402 } from "@inntris/x402-adapter";
import { Pool } from "pg";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { bindingInput, MutableClock } from "../helpers.js";

const databaseUrl = process.env.INNTRIS_TEST_POSTGRES_URL;
const postgres = databaseUrl === undefined ? describe.skip : describe;

postgres("PostgreSQL policy state", () => {
  const pool = new Pool({ connectionString: databaseUrl });
  const clock = new MutableClock();
  const signer = createPublicDemoSigner();
  let policyText: string;

  beforeAll(async () => {
    policyText = await readFile(resolve("policies/demo-x402-policy.yml"), "utf8");
    await migratePostgresStore(pool);
    await migratePostgresStore(pool);
  });

  beforeEach(async () => {
    await pool.query("DROP TRIGGER IF EXISTS fail_spend ON inntris.daily_spend");
    await pool.query("DROP FUNCTION IF EXISTS inntris.fail_spend() CASCADE");
    await pool.query(`
      TRUNCATE TABLE
        inntris.approval_claims,
        inntris.consumptions,
        inntris.daily_spend,
        inntris.decisions
      RESTART IDENTITY CASCADE
    `);
  });

  afterAll(async () => {
    await pool.end();
  });

  function provider(dailyLimit = "500.00") {
    const parsed = parsePolicyText(policyText);
    const policy = {
      ...parsed,
      limits: { ...parsed.limits, daily: dailyLimit },
    };
    const stateStore = new PostgresPolicyStateStore(pool);
    return {
      stateStore,
      provider: new LocalPolicyDecisionProvider({ policy, signer, clock, stateStore }),
    };
  }

  it("persists immutable decisions and accepts an identical retry", async () => {
    const { provider: decisionProvider, stateStore } = provider();
    const decision = await decisionProvider.evaluate(actionFromX402(bindingInput));
    const record = await stateStore.get(decision.decision_id);

    expect(record?.decision).toEqual(decision);
    await expect(stateStore.save(record!)).resolves.toBeUndefined();

    const changed = structuredClone(record!);
    changed.decision.reason_codes = ["DEFAULT_DENY"];
    await expect(stateStore.save(changed)).rejects.toThrow("immutable");
  });

  it("consumes once and makes a matching retry idempotent without double spend", async () => {
    const { provider: decisionProvider, stateStore } = provider();
    const decision = await decisionProvider.evaluate(actionFromX402(bindingInput));
    const input = {
      decision_id: decision.decision_id,
      action_hash: decision.action_hash,
      execution_ref: "postgres-idempotent",
    };

    const first = await decisionProvider.consume(input);
    const retry = await decisionProvider.consume(input);

    expect(first).toMatchObject({ success: true, status: "consumed" });
    expect(retry).toMatchObject({ success: true, status: "idempotent" });
    expect(await stateStore.getDailySpend("org_demo", "2026-07-29")).toBe("4.50");
  });

  it("allows only one concurrent execution reference", async () => {
    const { provider: decisionProvider, stateStore } = provider();
    const decision = await decisionProvider.evaluate(actionFromX402(bindingInput));

    const results = await Promise.all([
      decisionProvider.consume({
        decision_id: decision.decision_id,
        action_hash: decision.action_hash,
        execution_ref: "postgres-concurrent-a",
      }),
      decisionProvider.consume({
        decision_id: decision.decision_id,
        action_hash: decision.action_hash,
        execution_ref: "postgres-concurrent-b",
      }),
    ]);

    expect(results.filter((result) => result.status === "consumed")).toHaveLength(1);
    expect(results.filter((result) => result.status === "conflict")).toEqual([
      expect.objectContaining({ reason_code: "NONCE_ALREADY_CONSUMED" }),
    ]);
    expect(await stateStore.getDailySpend("org_demo", "2026-07-29")).toBe("4.50");
  });

  it("rechecks the daily limit atomically across independently issued decisions", async () => {
    const { provider: decisionProvider, stateStore } = provider("5.00");
    const action = actionFromX402(bindingInput);
    const [first, second] = await Promise.all([
      decisionProvider.evaluate(action),
      decisionProvider.evaluate(action),
    ]);

    const results = await Promise.all([
      decisionProvider.consume({
        decision_id: first.decision_id,
        action_hash: first.action_hash,
        execution_ref: "postgres-limit-a",
      }),
      decisionProvider.consume({
        decision_id: second.decision_id,
        action_hash: second.action_hash,
        execution_ref: "postgres-limit-b",
      }),
    ]);

    expect(results.filter((result) => result.status === "consumed")).toHaveLength(1);
    expect(results.filter((result) => result.status === "rejected")).toEqual([
      expect.objectContaining({ reason_code: "DAILY_LIMIT_EXCEEDED" }),
    ]);
    expect(await stateStore.getDailySpend("org_demo", "2026-07-29")).toBe("4.50");
  });

  it("rolls nonce consumption back when spend persistence fails", async () => {
    const { provider: decisionProvider, stateStore } = provider();
    const decision = await decisionProvider.evaluate(actionFromX402(bindingInput));
    const input = {
      decision_id: decision.decision_id,
      action_hash: decision.action_hash,
      execution_ref: "postgres-rollback",
    };
    await pool.query(`
      CREATE FUNCTION inntris.fail_spend() RETURNS trigger
      LANGUAGE plpgsql AS $$
      BEGIN
        RAISE EXCEPTION 'injected spend failure';
      END;
      $$
    `);
    await pool.query(`
      CREATE TRIGGER fail_spend
      BEFORE INSERT OR UPDATE ON inntris.daily_spend
      FOR EACH ROW EXECUTE FUNCTION inntris.fail_spend()
    `);

    await expect(decisionProvider.consume(input)).rejects.toThrow("injected spend failure");
    const consumed = await pool.query<{ count: string }>(
      "SELECT count(*)::text AS count FROM inntris.consumptions",
    );
    expect(consumed.rows[0]?.count).toBe("0");

    await pool.query("DROP TRIGGER fail_spend ON inntris.daily_spend");
    await pool.query("DROP FUNCTION inntris.fail_spend()");
    await expect(decisionProvider.consume(input)).resolves.toMatchObject({
      success: true,
      status: "consumed",
    });
    expect(await stateStore.getDailySpend("org_demo", "2026-07-29")).toBe("4.50");
  });

  it("claims one human approval across provider instances", async () => {
    const first = provider();
    const second = new LocalPolicyDecisionProvider({
      policy: first.provider.options.policy,
      signer,
      clock,
      stateStore: new PostgresPolicyStateStore(pool),
    });
    const action = actionFromX402({
      ...bindingInput,
      paymentRequirements: { ...bindingInput.paymentRequirements, amount: "80000000" },
    });
    const decision = await first.provider.evaluate(action);
    expect(decision.verdict).toBe("REQUIRE_APPROVAL");
    const input = {
      decision_id: decision.decision_id,
      granted: true,
      approval_reference: "postgres-approval",
      approver_ids: ["user_finance_lead"],
    };

    const results = await Promise.all([
      first.provider.resolveApproval(input),
      second.resolveApproval(input),
    ]);
    expect(results.filter((result) => result.success)).toHaveLength(1);
    expect(results.filter((result) => !result.success)).toEqual([
      expect.objectContaining({
        status: "conflict",
        reason_code: "APPROVAL_ALREADY_RESOLVED",
      }),
    ]);
  });
});
