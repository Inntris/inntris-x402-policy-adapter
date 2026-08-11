import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import {
  DefaultKyaAuthorityVerifier,
  InMemoryKyaNonceStore,
  KyaAuthorityPolicyV1Schema,
  KyaAuthorityPresentationSchema,
  ModernKyaDelegationVerifier,
  OfficialEddsaJcs2022Verifier,
  ProductionKyaDidResolver,
  UpstreamKyaRequestProofVerifier,
  VerifiedKyaAuthorityBindingV1Schema,
  hashKyaAuthorityPolicy,
  withoutKyaExtension,
} from "@inntris/kya-os-authority";
import { InntrisActionV1Schema, hashAction, hashCanonical } from "@inntris/decision-core";
import { verifyDecision, verifySignedDecision } from "@inntris/decision-verifier";

async function readJson(path: string): Promise<unknown> {
  return JSON.parse(await readFile(path, "utf8")) as unknown;
}

const forbiddenPrivateMaterialKeys = new Set([
  "api_key",
  "bearer_token",
  "d",
  "password",
  "private_jwk",
  "private_key",
  "secret",
]);

function assertNoPrivateMaterial(value: unknown, location: string): void {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => assertNoPrivateMaterial(entry, `${location}[${index}]`));
    return;
  }
  if (typeof value !== "object" || value === null) return;
  for (const [key, entry] of Object.entries(value)) {
    if (forbiddenPrivateMaterialKeys.has(key.toLowerCase())) {
      throw new Error(`Private material key ${key} found in public KYA artefact ${location}`);
    }
    assertNoPrivateMaterial(entry, `${location}.${key}`);
  }
}

const directory = resolve("evidence/kya-os");
const manifest = (await readJson(resolve(directory, "manifest.json"))) as Record<string, unknown>;
const policy = KyaAuthorityPolicyV1Schema.parse(
  await readJson(resolve(directory, "authority-policy.json")),
);
const binding = VerifiedKyaAuthorityBindingV1Schema.parse(
  await readJson(resolve(directory, "verified-authority-binding.json")),
);
const action = InntrisActionV1Schema.parse(
  await readJson(resolve(directory, "inntris-action.json")),
);
const presentation = KyaAuthorityPresentationSchema.parse(
  await readJson(resolve(directory, "valid-presentation.json")),
);
const decision = await readJson(resolve(directory, "signed-allow.json"));
const keyRegistry = await readJson(resolve("fixtures/keys/registry.json"));
for (const [name, value] of Object.entries({
  manifest,
  policy,
  binding,
  action,
  presentation,
  decision,
})) {
  assertNoPrivateMaterial(value, `evidence/kya-os/${name}`);
}
if (manifest.authority_policy_hash !== hashKyaAuthorityPolicy(policy)) {
  throw new Error("KYA authority policy hash mismatch");
}
if (manifest.expected_authority_hash !== binding.authority_hash) {
  throw new Error("KYA authority binding hash mismatch");
}
if (manifest.expected_action_hash !== hashAction(action)) {
  throw new Error("KYA action hash mismatch");
}
const clock = { now: () => new Date("2026-08-11T10:00:00.000Z") };
function authorityVerifier(resolver: ProductionKyaDidResolver) {
  return new DefaultKyaAuthorityVerifier({
    requestProof: new UpstreamKyaRequestProofVerifier({
      resolver,
      nonceStore: new InMemoryKyaNonceStore(),
      clock,
    }),
    delegation: new ModernKyaDelegationVerifier({
      signatures: new OfficialEddsaJcs2022Verifier(resolver),
      revocation: async () => ({ revoked: false, fresh: true }),
    }),
  });
}
const verified = await authorityVerifier(new ProductionKyaDidResolver()).verify({
  presentation,
  action: withoutKyaExtension(action),
  authorityPolicy: policy,
  expectedAudience: policy.expected_audiences[0] ?? "",
  now: clock.now(),
});
if (hashCanonical(verified.binding) !== hashCanonical(binding)) {
  throw new Error("KYA authority presentation does not reproduce the committed binding");
}
const result = verifyDecision({
  decision,
  action,
  keyRegistry,
  at: new Date("2026-08-11T10:00:30.000Z"),
  expectedPolicyVersion: "1",
});
if (!result.valid || result.verdict !== "ALLOW") {
  throw new Error(`KYA signed ALLOW did not verify: ${result.reason_codes.join(",")}`);
}
for (const filename of [
  "amount-over-delegation-block.json",
  "wrong-agent-block.json",
  "revoked-delegation-block.json",
]) {
  const block = await readJson(resolve(directory, filename));
  assertNoPrivateMaterial(block, `evidence/kya-os/${filename}`);
  const signed = verifySignedDecision(block, keyRegistry);
  if (!signed.valid || (block as { verdict?: unknown }).verdict !== "BLOCK") {
    throw new Error(`${filename} is not a valid signed BLOCK`);
  }
}
const fixtureHashes = manifest.fixture_hashes as Record<string, string>;
for (const [path, expected] of Object.entries(fixtureHashes)) {
  const fixturePath = resolve("fixtures/kya-os", path);
  const content = await readFile(fixturePath);
  const actual = `sha256:${createHash("sha256").update(content).digest("hex")}`;
  if (actual !== expected) throw new Error(`KYA fixture hash mismatch: ${path}`);
  assertNoPrivateMaterial(JSON.parse(content.toString("utf8")) as unknown, path);
}
const didWebPresentation = KyaAuthorityPresentationSchema.parse(
  await readJson(resolve("fixtures/kya-os/presentations/valid-did-web.json")),
);
if (didWebPresentation.profile !== "entity-card-v1") {
  throw new Error("Expected an entity-card-v1 did:web fixture");
}
const didWebDocument = await readJson(
  resolve("fixtures/kya-os/entity-card/did-web-agent-document.json"),
);
const didWebResolver = new ProductionKyaDidResolver({
  safeFetch: async (url) => {
    if (url !== "https://agent.example/.well-known/did.json") {
      throw new Error(`Unexpected did:web evidence URL: ${url}`);
    }
    return { ok: true, status: 200, json: async () => didWebDocument };
  },
});
const didWebProof = didWebPresentation.request_proof as { did?: unknown };
if (typeof didWebProof.did !== "string") throw new Error("Missing did:web proof DID");
await authorityVerifier(didWebResolver).verify({
  presentation: didWebPresentation,
  action: InntrisActionV1Schema.parse({
    ...withoutKyaExtension(action),
    agent_id: didWebProof.did,
  }),
  authorityPolicy: policy,
  expectedAudience: policy.expected_audiences[0] ?? "",
  now: clock.now(),
});
process.stdout.write("KYA EVIDENCE: PASS\n");
