/**
 * One process in the C4 cross-process race. Each worker opens its own pool and
 * attempts to consume the same decision at a coordinated wall-clock instant,
 * so the concurrency is real OS-level concurrency rather than interleaved
 * async work inside one event loop.
 */
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { createPublicDemoSigner } from "@inntris/decision-core";
import { LocalPolicyDecisionProvider, parsePolicyText } from "@inntris/policy-engine";
import { PostgresPolicyStateStore } from "@inntris/postgres-store";
import { Pool } from "pg";

const databaseUrl = process.env.INNTRIS_TEST_POSTGRES_URL;
const decisionId = process.env.C4_DECISION_ID;
const actionHash = process.env.C4_ACTION_HASH;
const executionRef = process.env.C4_EXECUTION_REF;
const startAtMs = Number(process.env.C4_START_AT_MS);

if (
  databaseUrl === undefined ||
  decisionId === undefined ||
  actionHash === undefined ||
  executionRef === undefined
) {
  throw new Error("C4 worker is missing required environment");
}

const pool = new Pool({ connectionString: databaseUrl, max: 2 });
try {
  const provider = new LocalPolicyDecisionProvider({
    policy: parsePolicyText(await readFile(resolve("policies/demo-x402-policy.yml"), "utf8")),
    signer: createPublicDemoSigner(),
    stateStore: new PostgresPolicyStateStore(pool),
  });

  // Warm the connection so the race measures the consume, not the handshake.
  await pool.query("SELECT 1");

  const spin = startAtMs - Date.now();
  if (spin > 0) await new Promise((wake) => setTimeout(wake, spin));

  const result = await provider.consume({
    decision_id: decisionId,
    action_hash: actionHash,
    execution_ref: executionRef,
  });
  process.stdout.write(`${JSON.stringify(result)}\n`);
} finally {
  await pool.end();
}
