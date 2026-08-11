import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import {
  completeVerifiedBinding,
  type KyaAuthorityRevalidationRecord,
} from "@inntris/kya-os-authority";
import { createPublicDemoSigner, hashAction, hashCanonical } from "@inntris/decision-core";
import { LocalPolicyDecisionProvider, parsePolicyText } from "@inntris/policy-engine";
import {
  migratePostgresStore,
  PostgresKyaAuthorityStateStore,
  PostgresKyaNonceStore,
  PostgresPolicyStateStore,
} from "@inntris/postgres-store";
import { actionFromX402 } from "@inntris/x402-adapter";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { bindingInput, MutableClock } from "../helpers.js";

const databaseUrl = process.env.INNTRIS_TEST_POSTGRES_URL;
const postgres = databaseUrl === undefined ? describe.skip : describe;
const HASH_A = `sha256:${"a".repeat(64)}` as const;
const HASH_B = `sha256:${"b".repeat(64)}` as const;

postgres("PostgreSQL KYA authority state", () => {
  const pool = new Pool({ connectionString: databaseUrl });
  const clock = new MutableClock();

  beforeAll(async () => {
    await migratePostgresStore(pool);
  });

  afterAll(async () => {
    await pool.end();
  });

  it("atomically consumes a nonce and preserves replay state across store instances", async () => {
    const first = new PostgresKyaNonceStore(pool);
    const did = `did:key:test-${randomUUID()}`;
    const input = {
      did,
      nonce: randomUUID(),
      consumedAt: new Date("2026-07-29T12:00:00.000Z"),
      expiresAt: new Date("2026-07-29T12:01:00.000Z"),
    };
    const results = await Promise.all([first.consume(input), first.consume(input)]);
    expect(results.sort()).toEqual(["consumed", "replay"]);
    expect(await new PostgresKyaNonceStore(pool).consume(input)).toBe("replay");
  });

  it("purges only expired nonces and permits safe reuse after expiry", async () => {
    const store = new PostgresKyaNonceStore(pool);
    const did = `did:key:expired-${randomUUID()}`;
    const nonce = randomUUID();
    await store.consume({
      did,
      nonce,
      consumedAt: new Date("2026-07-29T11:00:00.000Z"),
      expiresAt: new Date("2026-07-29T11:01:00.000Z"),
    });
    expect(await store.purgeExpired(new Date("2026-07-29T12:00:00.000Z"))).toBeGreaterThan(0);
    expect(
      await store.consume({
        did,
        nonce,
        consumedAt: new Date("2026-07-29T12:00:00.000Z"),
        expiresAt: new Date("2026-07-29T12:01:00.000Z"),
      }),
    ).toBe("consumed");
  });

  it("keeps decision authority immutable and revalidation history append only", async () => {
    const policy = parsePolicyText(
      await readFile(resolve("policies/demo-x402-policy.yml"), "utf8"),
    );
    const policyStore = new PostgresPolicyStateStore(pool);
    const provider = new LocalPolicyDecisionProvider({
      policy,
      signer: createPublicDemoSigner(),
      clock,
      stateStore: policyStore,
    });
    const action = actionFromX402(bindingInput);
    const decision = await provider.evaluate(action);
    const binding = completeVerifiedBinding({
      version: "inntris-kya-authority-binding-v1",
      status: "verified",
      profile: "entity-card-v1",
      protocol_version: "1.0.0",
      reference_implementation: { package: "@kya-os/mcp", version: "1.12.0" },
      authority_policy_hash: HASH_A,
      presentation_hash: HASH_B,
      proof_hash: HASH_A,
      request_hash: HASH_B,
      delegation_chain_hash: HASH_A,
      entity_card_hash: null,
      agent_did: "did:key:agent",
      responsible_party_did: "did:key:responsible-party",
      principal_did: null,
      proof_assurance: "L3-minus",
      invocation_target: "did:web:api.example:payments",
      allowed_action: "payments.transfer",
      max_amount: "500.00",
      currency: "USD",
      delegation_depth: 1,
      revocation_fresh: true,
      signatures_verified: true,
      verified_at: clock.now().toISOString(),
      authority_expires_at: new Date(clock.now().getTime() + 60_000).toISOString(),
    });
    const record = {
      decision_id: decision.decision_id,
      action_hash: hashAction(action),
      action,
      binding,
      created_at: clock.now().toISOString(),
    };
    const first = new PostgresKyaAuthorityStateStore(pool);
    await first.saveDecisionAuthority(record);
    await expect(first.saveDecisionAuthority(record)).resolves.toBeUndefined();
    expect(
      await new PostgresKyaAuthorityStateStore(pool).getDecisionAuthority(decision.decision_id),
    ).toEqual(record);
    await expect(
      first.saveDecisionAuthority({ ...record, action_hash: hashCanonical({ changed: true }) }),
    ).rejects.toThrow("immutable");

    const verified: KyaAuthorityRevalidationRecord = {
      id: randomUUID(),
      decision_id: decision.decision_id,
      action_hash: record.action_hash,
      kind: "consumption",
      execution_ref: `execution-${randomUUID()}`,
      approval_reference: null,
      presentation_hash: HASH_B,
      authority_hash: binding.authority_hash,
      status: "verified",
      reason_code: null,
      verified_at: clock.now().toISOString(),
    };
    await first.appendRevalidation(verified);
    await first.appendRevalidation({ ...verified, id: randomUUID() });
    expect(
      await new PostgresKyaAuthorityStateStore(pool).getSuccessfulExecutionRevalidation({
        decisionId: decision.decision_id,
        actionHash: record.action_hash,
        executionRef: verified.execution_ref!,
      }),
    ).toEqual(verified);
    await first.appendRevalidation({
      ...verified,
      id: randomUUID(),
      execution_ref: `execution-${randomUUID()}`,
    });
    const count = await pool.query<{ count: string }>(
      "SELECT count(*)::text AS count FROM inntris.kya_authority_revalidations WHERE decision_id = $1",
      [decision.decision_id],
    );
    expect(count.rows[0]?.count).toBe("2");
  });
});
