import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import {
  Ed25519SigningProvider,
  InMemoryMetrics,
  buildKeyRegistryEntry,
  createPublicDemoSigner,
  type SigningProvider,
} from "@inntris/decision-core";
import { LocalPolicyDecisionProvider, loadPolicyFile } from "@inntris/policy-engine";
import { assertPostgresStoreReady, PostgresPolicyStateStore } from "@inntris/postgres-store";
import { Pool } from "pg";

import { buildDemoApi } from "./app.js";

async function loadSigner(): Promise<SigningProvider> {
  const direct = process.env.INNTRIS_SIGNING_SEED_BASE64URL;
  const file = process.env.INNTRIS_SIGNING_SEED_FILE;
  const demoMode = process.env.INNTRIS_DEMO_MODE === "true";
  const configured = [direct !== undefined, file !== undefined, demoMode].filter(Boolean).length;
  if (configured !== 1) {
    throw new Error(
      "Configure exactly one signing source: seed environment variable, mounted file or explicit demo mode",
    );
  }
  if (demoMode) {
    return createPublicDemoSigner();
  }
  let seed: string;
  if (direct !== undefined) {
    seed = direct;
  } else if (file !== undefined) {
    seed = (await readFile(resolve(file), "utf8")).trim();
  } else {
    throw new Error("No signing seed source was configured");
  }
  return Ed25519SigningProvider.fromBase64UrlSeed(
    process.env.INNTRIS_SIGNING_KEY_ID ?? "dev-key-1",
    seed,
  );
}

const signer = await loadSigner();
const metrics = new InMemoryMetrics();
const policy = await loadPolicyFile(
  resolve(process.env.INNTRIS_POLICY_FILE ?? "policies/demo-x402-policy.yml"),
);
const postgresUrl = process.env.INNTRIS_POSTGRES_URL?.trim();
const pool =
  postgresUrl === undefined || postgresUrl === ""
    ? undefined
    : new Pool({
        connectionString: postgresUrl,
      });
if (pool !== undefined) {
  await assertPostgresStoreReady(pool);
}
const provider = new LocalPolicyDecisionProvider({
  policy,
  signer,
  metrics,
  ...(pool === undefined ? {} : { stateStore: new PostgresPolicyStateStore(pool) }),
});
const keyRegistry = {
  version: "inntris-key-registry-v1" as const,
  keys: [
    buildKeyRegistryEntry(signer, {
      notBefore: new Date("2026-01-01T00:00:00.000Z"),
    }),
  ],
};
const app = await buildDemoApi({
  provider,
  keyRegistry,
  expectedPolicyVersion: policy.policy_version,
  serviceApiKey:
    process.env.INNTRIS_SERVICE_API_KEY === "" ? undefined : process.env.INNTRIS_SERVICE_API_KEY,
  metrics,
});
if (pool !== undefined) {
  app.addHook("onClose", async () => {
    await pool.end();
  });
}

await app.listen({
  host: process.env.INNTRIS_API_HOST ?? "127.0.0.1",
  port: Number.parseInt(process.env.INNTRIS_API_PORT ?? "3402", 10),
});
