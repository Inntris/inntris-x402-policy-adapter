import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import {
  Ed25519SigningProvider,
  InMemoryMetrics,
  buildKeyRegistryEntry,
  createPublicDemoSigner,
  type DecisionProvider,
  type SigningProvider,
} from "@inntris/decision-core";
import {
  RemoteEd25519SigningProvider,
  assertRotationRegistry,
  assertSigningProviderRegistered,
  loadKeyRegistryFile,
} from "@inntris/managed-signing";
import {
  assertSeparateSigningIdentities,
  MtpAuthorityClient,
  MtpCompositeDecisionProvider,
} from "@inntris/mtp-authority";
import { LocalPolicyDecisionProvider, loadPolicyFile } from "@inntris/policy-engine";
import {
  assertPostgresStoreReady,
  PostgresMtpAuthorityStateStore,
  PostgresPolicyStateStore,
} from "@inntris/postgres-store";
import { Pool } from "pg";

import { buildDemoApi } from "./app.js";

function configuredValue(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed === "" ? undefined : trimmed;
}

async function loadSigner(): Promise<SigningProvider> {
  const direct = configuredValue(process.env.INNTRIS_SIGNING_SEED_BASE64URL);
  const file = configuredValue(process.env.INNTRIS_SIGNING_SEED_FILE);
  const demoMode = process.env.INNTRIS_DEMO_MODE === "true";
  const managedUrl = configuredValue(process.env.INNTRIS_MANAGED_SIGNER_URL);
  const configured = [
    direct !== undefined,
    file !== undefined,
    demoMode,
    managedUrl !== undefined,
  ].filter(Boolean).length;
  if (configured !== 1) {
    throw new Error(
      "Configure exactly one signing source: seed environment variable, mounted file, managed signer or explicit demo mode",
    );
  }
  if (demoMode) {
    return createPublicDemoSigner();
  }
  if (managedUrl !== undefined) {
    const bearerToken = process.env.INNTRIS_MANAGED_SIGNER_BEARER_TOKEN?.trim();
    const publicKey = process.env.INNTRIS_MANAGED_SIGNER_PUBLIC_KEY_BASE64URL?.trim();
    if (bearerToken === undefined || publicKey === undefined) {
      throw new Error(
        "Managed signing requires INNTRIS_MANAGED_SIGNER_BEARER_TOKEN and INNTRIS_MANAGED_SIGNER_PUBLIC_KEY_BASE64URL",
      );
    }
    return new RemoteEd25519SigningProvider({
      endpointUrl: managedUrl,
      bearerToken,
      keyId: configuredValue(process.env.INNTRIS_SIGNING_KEY_ID) ?? "decision-key-1",
      publicKeyBase64Url: publicKey,
    });
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

async function loadMtpSigner(): Promise<SigningProvider> {
  const direct = configuredValue(process.env.INNTRIS_MTP_SIGNING_SEED_BASE64URL);
  const file = configuredValue(process.env.INNTRIS_MTP_SIGNING_SEED_FILE);
  const managedUrl = configuredValue(process.env.INNTRIS_MTP_MANAGED_SIGNER_URL);
  const configured = [direct !== undefined, file !== undefined, managedUrl !== undefined].filter(
    Boolean,
  ).length;
  if (configured !== 1) {
    throw new Error(
      "Configure exactly one MTP signing source: seed environment variable, mounted file or managed signer",
    );
  }
  if (managedUrl !== undefined) {
    const bearerToken = process.env.INNTRIS_MTP_MANAGED_SIGNER_BEARER_TOKEN?.trim();
    const publicKey = process.env.INNTRIS_MTP_MANAGED_SIGNER_PUBLIC_KEY_BASE64URL?.trim();
    if (bearerToken === undefined || publicKey === undefined) {
      throw new Error("Managed MTP signing requires its bearer token and public key configuration");
    }
    return new RemoteEd25519SigningProvider({
      endpointUrl: managedUrl,
      bearerToken,
      keyId: configuredValue(process.env.INNTRIS_MTP_SIGNING_KEY_ID) ?? "mtp-agent-key-1",
      publicKeyBase64Url: publicKey,
    });
  }
  let seed: string;
  if (direct !== undefined) {
    seed = direct;
  } else if (file !== undefined) {
    seed = (await readFile(resolve(file), "utf8")).trim();
  } else {
    throw new Error("No MTP signing seed source was configured");
  }
  return Ed25519SigningProvider.fromBase64UrlSeed(
    process.env.INNTRIS_MTP_SIGNING_KEY_ID ?? "mtp-agent-key-1",
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
const localProvider = new LocalPolicyDecisionProvider({
  policy,
  signer,
  metrics,
  ...(pool === undefined ? {} : { stateStore: new PostgresPolicyStateStore(pool) }),
});
const mtpApiUrl = process.env.INNTRIS_MTP_API_URL?.trim();
let provider: DecisionProvider = localProvider;
if (mtpApiUrl !== undefined && mtpApiUrl !== "") {
  const mtpAgentId = process.env.INNTRIS_MTP_AGENT_ID?.trim();
  if (mtpAgentId === undefined || mtpAgentId === "") {
    throw new Error("INNTRIS_MTP_AGENT_ID is required when MTP authority is enabled");
  }
  if (pool === undefined) {
    throw new Error("INNTRIS_POSTGRES_URL is required when MTP authority is enabled");
  }
  const mtpSigner = await loadMtpSigner();
  assertSeparateSigningIdentities(signer, mtpSigner);
  provider = new MtpCompositeDecisionProvider({
    provider: localProvider,
    client: new MtpAuthorityClient({
      apiUrl: mtpApiUrl,
      agentId: mtpAgentId,
      signer: mtpSigner,
      policyHash: process.env.INNTRIS_MTP_POLICY_HASH,
    }),
    stateStore: new PostgresMtpAuthorityStateStore(pool),
  });
}
const registryFile = process.env.INNTRIS_KEY_REGISTRY_FILE?.trim();
if (configuredValue(process.env.INNTRIS_MANAGED_SIGNER_URL) !== undefined && !registryFile) {
  throw new Error("INNTRIS_KEY_REGISTRY_FILE is required with managed Decision Envelope signing");
}
const keyRegistry =
  registryFile === undefined || registryFile === ""
    ? {
        version: "inntris-key-registry-v1" as const,
        keys: [
          buildKeyRegistryEntry(signer, {
            notBefore: new Date("2026-01-01T00:00:00.000Z"),
          }),
        ],
      }
    : assertSigningProviderRegistered(
        signer,
        assertRotationRegistry(await loadKeyRegistryFile(resolve(registryFile))),
      );
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
