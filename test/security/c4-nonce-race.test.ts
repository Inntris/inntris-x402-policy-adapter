import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { promisify } from "node:util";

import { buildKeyRegistryEntry, createPublicDemoSigner } from "@inntris/decision-core";
import { LocalPolicyDecisionProvider, parsePolicyText } from "@inntris/policy-engine";
import {
  migratePostgresStore,
  PostgresExecutionReconciliationStore,
  PostgresPolicyStateStore,
} from "@inntris/postgres-store";
import { InntrisX402Guard } from "@inntris/x402-adapter";
import { Pool } from "pg";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import {
  compliantFacilitator,
  FakeFacilitator,
  GuardedResourceServer,
  honestInput,
  InMemorySpendState,
  MutableClock,
  paymentPayload,
  permissiveFacilitator,
  securityContext,
  type SecurityContext,
} from "./harness.js";
import { actionFromX402 } from "@inntris/x402-adapter";

const run = promisify(execFile);
import { flushEvidence, recordEvidence } from "./evidence.js";

const databaseUrl = process.env.INNTRIS_TEST_POSTGRES_URL;
const postgres = databaseUrl === undefined ? describe.skip : describe;

/**
 * C4. Sequential replay is the easy case and the adapter already handles it.
 * The reference paper's validated free-shopping exploit is the concurrent one:
 * verification is stateless and does not reserve the nonce, so many parallel
 * requests can all pass before any settles. This runs the real atomic
 * PostgreSQL store rather than the in-memory reference implementation, because
 * the question is whether nonce reservation is atomic at the database level.
 */
postgres("C4 concurrent nonce race", () => {
  const pool = new Pool({ connectionString: databaseUrl, max: 32 });
  let policyText: string;

  beforeAll(async () => {
    policyText = await readFile(resolve("policies/demo-x402-policy.yml"), "utf8");
    await migratePostgresStore(pool);
  });

  beforeEach(async () => {
    await pool.query(`
      TRUNCATE TABLE
        inntris.execution_operations,
        inntris.approval_claims,
        inntris.consumptions,
        inntris.daily_spend,
        inntris.decisions
      RESTART IDENTITY CASCADE
    `);
  });

  afterAll(async () => {
    await flushEvidence("c4-nonce-race");
    await pool.end();
  });

  async function durableContext(
    clock: MutableClock = new MutableClock(),
  ): Promise<SecurityContext> {
    const signer = createPublicDemoSigner();
    const keyRegistry = {
      version: "inntris-key-registry-v1" as const,
      keys: [buildKeyRegistryEntry(signer, { notBefore: new Date("2026-01-01T00:00:00.000Z") })],
    };
    const stateStore = new PostgresPolicyStateStore(pool);
    const provider = new LocalPolicyDecisionProvider({
      policy: parsePolicyText(policyText),
      signer,
      clock,
      stateStore,
    });
    const reconciliationStore = new PostgresExecutionReconciliationStore(pool);
    const guard = new InntrisX402Guard({
      provider,
      keyRegistry,
      expectedPolicyVersion: "1",
      clock,
      reconciliationStore,
    });
    return { clock, provider, guard, keyRegistry, reconciliationStore };
  }

  /**
   * Fires N accesses concurrently against one decision. Each carries its own
   * execution reference, which is the attacker's best case: distinct
   * references cannot be collapsed by idempotency and must be refused on the
   * nonce instead.
   */
  async function race(
    concurrency: number,
    facilitator: FakeFacilitator,
  ): Promise<{ released: number; settled: number; reasons: string[] }> {
    const context = await durableContext();
    const server = new GuardedResourceServer(context, facilitator);
    const decision = await context.guard.authorise(honestInput);
    expect(decision.verdict).toBe("ALLOW");

    const outcomes = await Promise.all(
      Array.from({ length: concurrency }, async (_unused, index) =>
        server.access({
          authorisationInput: honestInput,
          payload: paymentPayload({}),
          executionRef: `c4-${facilitator.label}-${concurrency}-${index}`,
          decision,
        }),
      ),
    );

    return {
      released: outcomes.filter((outcome) => outcome.resource_served).length,
      settled: facilitator.settleCalls.length,
      reasons: [...new Set(outcomes.flatMap((outcome) => outcome.reason_codes))],
    };
  }

  for (const concurrency of [2, 5, 20]) {
    for (const [label, build] of [
      ["compliant", compliantFacilitator],
      ["permissive", permissiveFacilitator],
    ] as const) {
      it(`releases at most once for N=${concurrency} against the ${label} facilitator`, async () => {
        const facilitator = build();
        const result = await race(concurrency, facilitator);

        recordEvidence({
          id: `C4:n${concurrency}:${label}`,
          deliverable: "C4",
          attack: `Concurrent nonce race — ${concurrency} parallel requests carrying one authorisation, ${label} facilitator`,
          status: result.released === 1 && result.settled === 1 ? "PASS" : "KNOWN_GAP",
          expectation:
            "Releases equals settled transactions equals one, however many requests arrive in parallel.",
          observed: `${concurrency} parallel accesses on one decision against the durable PostgreSQL store: ${result.released} released, ${result.settled} settlement calls. Refusal reasons: ${result.reasons.join(", ") || "none"}.`,
          enforcement: result.released === 1 && result.settled === 1 ? "INNTRIS" : "NONE",
          reason_codes: result.reasons,
          settlement_invoked: result.settled > 0,
          resource_served: result.released > 0,
          notes:
            "Atomic PostgreSQL policy state store and PostgreSQL reconciliation store. Each request carries a distinct execution reference, so idempotency cannot collapse them and the nonce must do the work.",
        });

        expect(result.released).toBe(1);
        expect(result.settled).toBe(1);
      });
    }
  }

  it("control: the single-process race does not discriminate an atomic store", async () => {
    // The same race against the in-memory stores. The in-memory nonce store's
    // check-and-set is synchronous within one tick, so it also releases once.
    // That is the point: a single-process Promise.all cannot tell an
    // atomically-reserved nonce from one protected only by the event loop, so
    // the cross-process case below is what actually answers C4.
    const context = await securityContext({
      reconciliation: true,
      spendState: new InMemorySpendState(),
    });
    const facilitator = permissiveFacilitator();
    const server = new GuardedResourceServer(context, facilitator);
    const decision = await context.guard.authorise(honestInput);

    const outcomes = await Promise.all(
      Array.from({ length: 20 }, async (_unused, index) =>
        server.access({
          authorisationInput: honestInput,
          payload: paymentPayload({}),
          executionRef: `c4-control-${index}`,
          decision,
        }),
      ),
    );
    const released = outcomes.filter((outcome) => outcome.resource_served).length;

    recordEvidence({
      id: "C4:control-in-memory",
      deliverable: "C4",
      attack: "Control — same 20-way race against the in-memory stores",
      status: "PASS",
      expectation: "Recorded to establish what the single-process race can and cannot demonstrate.",
      observed: `${released} released, ${facilitator.settleCalls.length} settlement calls against the in-memory stores. The in-process race is won by the event loop rather than by the database, so a passing single-process result is not evidence of durable atomicity. The cross-process case supplies that evidence.`,
      enforcement: "INNTRIS",
      reason_codes: [],
      settlement_invoked: facilitator.settleCalls.length > 0,
      resource_served: released > 0,
    });

    expect(released).toBe(1);
  });

  it("releases at most once across 20 separate OS processes", async () => {
    // The workers run on the real system clock, so the decision must be signed
    // against real time or every worker simply sees an expired decision.
    const context = await durableContext(new MutableClock(new Date()));
    const decision = await context.guard.authorise(honestInput);
    const actionHash = actionFromX402(honestInput);
    expect(decision.verdict).toBe("ALLOW");
    expect(decision.action_hash).toBe(
      (await import("@inntris/decision-core")).hashAction(actionHash),
    );

    const concurrency = 20;
    // A shared wall-clock start so the workers converge on the same instant.
    const startAtMs = Date.now() + 1_500;
    const workers = Array.from({ length: concurrency }, async (_unused, index) =>
      run("pnpm", ["exec", "tsx", "test/security/c4-race-worker.ts"], {
        cwd: resolve("."),
        env: {
          ...process.env,
          C4_DECISION_ID: decision.decision_id,
          C4_ACTION_HASH: decision.action_hash,
          C4_EXECUTION_REF: `c4-xproc-${index}`,
          C4_START_AT_MS: String(startAtMs),
        },
      }).then(
        (completed) =>
          JSON.parse(completed.stdout.trim()) as { status: string; reason_code?: string },
      ),
    );

    const results = await Promise.all(workers);
    const consumed = results.filter((result) => result.status === "consumed").length;
    const conflicts = results.filter((result) => result.status === "conflict").length;
    const tally = results.reduce<Record<string, number>>((counts, result) => {
      const key =
        result.reason_code === undefined ? result.status : `${result.status}:${result.reason_code}`;
      counts[key] = (counts[key] ?? 0) + 1;
      return counts;
    }, {});

    recordEvidence({
      id: "C4:cross-process",
      deliverable: "C4",
      attack:
        "Concurrent nonce race across 20 separate OS processes, each with its own connection pool",
      status: consumed === 1 ? "PASS" : "KNOWN_GAP",
      expectation:
        "Exactly one process consumes the nonce; every other is refused. This is the case the reference paper exploited.",
      observed: `${concurrency} processes converged on one decision at a shared wall-clock instant: ${consumed} consumed, ${conflicts} conflict, ${results.length - consumed - conflicts} other. Statuses: ${JSON.stringify(tally)}. Reservation is a single INSERT ... ON CONFLICT DO NOTHING RETURNING inside a transaction (postgres-store/src/store.ts:141), so exactly one transaction can return a row.`,
      enforcement: consumed === 1 ? "INNTRIS" : "NONE",
      reason_codes: consumed === 1 ? ["NONCE_ALREADY_CONSUMED"] : [],
      settlement_invoked: false,
      resource_served: consumed > 0,
      notes:
        "Answers the question the F-2 redesign depends on: nonce reservation is already atomic at the database level, so F-2 does not require a store redesign — it requires the non-durable default to stop being the default.",
    });

    expect(consumed).toBe(1);
    expect(conflicts).toBe(concurrency - 1);
  });
});
