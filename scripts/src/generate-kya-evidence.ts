import { createHash, createPrivateKey, createPublicKey, sign as signBytes } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

import { createSignCryptosuite } from "@digitalbazaar/eddsa-jcs-2022-cryptosuite";
import {
  createPublicDemoSigner,
  createSignedDecision,
  hashPolicyObject,
  type Clock,
  type InntrisActionV1,
} from "@inntris/decision-core";
import {
  DefaultKyaAuthorityVerifier,
  InMemoryKyaNonceStore,
  KyaAuthorityError,
  ModernKyaDelegationVerifier,
  OfficialEddsaJcs2022Verifier,
  ProductionKyaDidResolver,
  UpstreamKyaRequestProofVerifier,
  attachKyaAuthorityBinding,
  createRejectedKyaBinding,
  hashKyaAuthorityPolicy,
  type KyaAuthorityPolicyV1,
  type KyaEntityCardAuthorityPresentation,
} from "@inntris/kya-os-authority";
import { KYA_OS_CARD_PROOF_META_KEY, buildCardProof, ed25519SignerFromJwk } from "@kya-os/mcp/card";
import { didKeyFragment, generateDidKeyFromBytes } from "@kya-os/mcp";
import { evaluatePolicy, type InntrisPolicyV1, ZeroSpendState } from "@inntris/policy-engine";
import { encode } from "base58-universal";
import { format } from "prettier";

// TEST ONLY deterministic identities. Never use these derivation bytes in production.
const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const NOW = new Date("2026-08-11T10:00:00.000Z");
const AUDIENCE = "did:web:inntris.example:verifier";
const TARGET = "did:web:api.example:payments";
const RESOURCE = "https://merchant.example/api/data";
const PAYEE = "did:web:merchant.example";

interface TestIdentity {
  did: string;
  kid: string;
  privateJwk: { kty: "OKP"; crv: "Ed25519"; x: string; d: string };
  publicJwk: { kty: "OKP"; crv: "Ed25519"; x: string };
  privateKey: ReturnType<typeof createPrivateKey>;
}

function identity(fill: number, didOverride?: string): TestIdentity {
  const privateKey = createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.alloc(32, fill)]),
    format: "der",
    type: "pkcs8",
  });
  const privateJwk = privateKey.export({ format: "jwk" });
  const publicJwk = createPublicKey(privateKey).export({ format: "jwk" });
  if (privateJwk.x === undefined || privateJwk.d === undefined || publicJwk.x === undefined) {
    throw new Error("Unable to derive TEST ONLY Ed25519 identity");
  }
  const generatedDid = generateDidKeyFromBytes(Buffer.from(publicJwk.x, "base64url"));
  const did = didOverride ?? generatedDid;
  return {
    did,
    kid: didOverride === undefined ? `${did}#${didKeyFragment(did)}` : `${did}#key-1`,
    privateJwk: { kty: "OKP", crv: "Ed25519", x: privateJwk.x, d: privateJwk.d },
    publicJwk: { kty: "OKP", crv: "Ed25519", x: publicJwk.x },
    privateKey,
  };
}

async function signCredential(
  unsigned: Record<string, unknown>,
  issuer: TestIdentity,
): Promise<Record<string, unknown>> {
  const proof: Record<string, unknown> = {
    type: "DataIntegrityProof",
    cryptosuite: "eddsa-jcs-2022",
    created: NOW.toISOString(),
    verificationMethod: issuer.kid,
    proofPurpose: "assertionMethod",
  };
  const suite = createSignCryptosuite();
  const data = await suite.createVerifyData({
    cryptosuite: suite,
    document: structuredClone(unsigned),
    proof,
  });
  return {
    ...unsigned,
    proof: { ...proof, proofValue: `z${encode(signBytes(null, data, issuer.privateKey))}` },
  };
}

async function presentation(input: {
  root: TestIdentity;
  intermediary: TestIdentity;
  agent: TestIdentity;
  nonce: string;
  amount?: string;
  maxAmount?: string;
  l3?: boolean;
}): Promise<KyaEntityCardAuthorityPresentation> {
  const amount = input.amount ?? "42.00";
  const maxAmount = input.maxAmount ?? "400.00";
  const request = {
    method: "tools/call",
    params: {
      name: "payments.transfer",
      arguments: { to: PAYEE, amount, currency: "USD", resource: TARGET },
    },
  } as const;
  const proofSigner = await ed25519SignerFromJwk({
    did: input.agent.did,
    kid: input.agent.kid,
    privateJwk: input.agent.privateJwk,
  });
  const proofEnvelope = await buildCardProof(request, proofSigner, {
    audience: AUDIENCE,
    nonce: input.nonce,
    ttlSec: 60,
    now: () => NOW.getTime(),
  });
  const rootExpiry = new Date(NOW.getTime() + 300_000).toISOString();
  const leafExpiry = new Date(NOW.getTime() + 240_000).toISOString();
  const rootCredential = await signCredential(
    {
      "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://w3id.org/security/zcap/v1",
        "https://kya-os.org/ns/delegation/v1",
      ],
      id: "urn:uuid:00000000-0000-4000-8000-000000000041",
      type: ["VerifiableCredential", "DelegationCredential"],
      issuer: input.root.did,
      validFrom: new Date(NOW.getTime() - 60_000).toISOString(),
      validUntil: rootExpiry,
      credentialSubject: {
        id: "urn:zcap:kya-root",
        invoker: input.intermediary.did,
        parentCapability: TARGET,
        invocationTarget: TARGET,
        allowedAction: ["payments.transfer"],
        caveats: [
          { type: "MaxAmount", limit: "500.00", currency: "USD" },
          { type: "ValidUntil", date: rootExpiry },
        ],
      },
      credentialStatus: {
        type: "BitstringStatusListEntry",
        statusPurpose: "revocation",
        statusListIndex: "41",
        statusListCredential: "https://status.example/kya/root",
      },
    },
    input.root,
  );
  const leafCredential = await signCredential(
    {
      "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://w3id.org/security/zcap/v1",
        "https://kya-os.org/ns/delegation/v1",
      ],
      id: "urn:uuid:00000000-0000-4000-8000-000000000042",
      type: ["VerifiableCredential", "DelegationCredential"],
      issuer: input.intermediary.did,
      validFrom: new Date(NOW.getTime() - 30_000).toISOString(),
      validUntil: leafExpiry,
      credentialSubject: {
        id: "urn:zcap:kya-leaf",
        invoker: input.agent.did,
        parentCapability: "urn:zcap:kya-root",
        invocationTarget: TARGET,
        allowedAction: ["payments.transfer"],
        caveats: [
          { type: "MaxAmount", limit: maxAmount, currency: "USD" },
          { type: "ValidUntil", date: leafExpiry },
        ],
      },
      credentialStatus: {
        type: "BitstringStatusListEntry",
        statusPurpose: "revocation",
        statusListIndex: "42",
        statusListCredential: "https://status.example/kya/leaf",
      },
    },
    input.intermediary,
  );
  return {
    profile: "entity-card-v1",
    request,
    request_proof: proofEnvelope[KYA_OS_CARD_PROOF_META_KEY],
    delegation_chain: [rootCredential, leafCredential],
    ...(input.l3 ? { token_cnf_jkt: proofSigner.jkt } : {}),
  };
}

function action(agentDid: string, responsiblePartyDid: string, amount = "42.00"): InntrisActionV1 {
  return {
    version: "inntris-action-v1",
    principal_id: responsiblePartyDid,
    agent_id: agentDid,
    action_type: "financial_transaction",
    rail: "x402",
    protocol_reference: {
      type: "x402",
      resource: RESOURCE,
      scheme: "exact",
      payment_requirements_hash: `sha256:${"0".repeat(64)}`,
      payment_payload_hash: null,
    },
    transaction: {
      amount,
      asset: "USDC",
      network: "eip155:8453",
      payee: PAYEE,
      purpose: "research_api",
    },
  };
}

const root = identity(41);
const intermediary = identity(42);
const agent = identity(43);
const didWebAgent = identity(44, "did:web:agent.example");
const authorityPolicy: KyaAuthorityPolicyV1 = {
  version: 1,
  policy_id: "demo-kya-authority",
  policy_version: "1",
  mode: "required",
  profiles: ["entity-card-v1", "legacy-v1"],
  expected_audiences: [AUDIENCE],
  accepted_did_methods: ["did:key", "did:web"],
  responsible_parties: [root.did],
  allowed_actions: ["payments.transfer"],
  min_proof_assurance: "L3-minus",
  require_fresh_revocation: true,
  require_max_amount: true,
  max_delegation_depth: 10,
  principal_source: "responsible_party",
  resource_bindings: [{ inntris_resource: RESOURCE, kya_invocation_target: TARGET }],
  currency_bindings: [{ inntris_asset: "USDC", kya_currency: "USD" }],
};
const organisationalPolicy: InntrisPolicyV1 = {
  version: 1,
  policy_id: "kya-evidence-policy",
  policy_version: "1",
  defaults: { verdict: "BLOCK", decision_ttl_seconds: 60 },
  rails: { x402: { allowed_networks: ["eip155:8453"], allowed_assets: ["USDC"] } },
  limits: { per_transaction: "100.00", daily: "500.00" },
  approval: { require_human_above: "75.00" },
  merchants: [
    {
      merchant_id: "kya-evidence-merchant",
      payees: [PAYEE],
      purposes: ["research_api"],
      resources: [RESOURCE],
      per_transaction_limit: "100.00",
    },
  ],
  time_windows: {
    timezone: "UTC",
    allowed_weekdays: ["MONDAY", "TUESDAY", "WEDNESDAY", "THURSDAY", "FRIDAY"],
    start: "06:00",
    end: "22:00",
  },
};
const clock: Clock = { now: () => new Date(NOW) };
const resolver = new ProductionKyaDidResolver();

function verifier(revoked = false) {
  return new DefaultKyaAuthorityVerifier({
    requestProof: new UpstreamKyaRequestProofVerifier({
      resolver,
      nonceStore: new InMemoryKyaNonceStore(),
      clock,
    }),
    delegation: new ModernKyaDelegationVerifier({
      signatures: new OfficialEddsaJcs2022Verifier(resolver),
      revocation: async () => ({ revoked, fresh: true }),
    }),
  });
}

const validPresentation = await presentation({
  root,
  intermediary,
  agent,
  nonce: "AQIDBAUGBwgJCgsMDQ4PMA",
});
const unboundAction = action(agent.did, root.did);
const verified = await verifier().verify({
  presentation: validPresentation,
  action: unboundAction,
  authorityPolicy,
  expectedAudience: AUDIENCE,
  now: NOW,
});
const boundAction = attachKyaAuthorityBinding(unboundAction, verified.binding);
const evaluation = await evaluatePolicy({
  action: boundAction,
  policy: organisationalPolicy,
  spendState: new ZeroSpendState(),
  clock,
});
const signer = createPublicDemoSigner();
const allow = await createSignedDecision({
  action: boundAction,
  evaluation,
  policyHash: hashPolicyObject(organisationalPolicy),
  policyVersion: organisationalPolicy.policy_version,
  decisionTtlSeconds: 60,
  signer,
  clock,
  decisionId: "018f0000-0000-7000-8000-000000000401",
  nonce: "a3lhLWV2aWRlbmNlLWFsbG93",
});

async function blockEvidence(input: {
  presentation: KyaEntityCardAuthorityPresentation;
  action: InntrisActionV1;
  revoked?: boolean;
  decisionId: string;
  nonce: string;
}) {
  let failure: KyaAuthorityError | undefined;
  try {
    await verifier(input.revoked).verify({
      presentation: input.presentation,
      action: input.action,
      authorityPolicy,
      expectedAudience: AUDIENCE,
      now: NOW,
    });
  } catch (error) {
    if (error instanceof KyaAuthorityError) failure = error;
    else throw error;
  }
  if (failure === undefined) throw new Error("Expected KYA evidence vector to fail");
  const rejectedAction = attachKyaAuthorityBinding(
    input.action,
    createRejectedKyaBinding({
      policy: authorityPolicy,
      presentation: input.presentation,
      failureStage: failure.failureStage,
    }),
  );
  return createSignedDecision({
    action: rejectedAction,
    evaluation: {
      verdict: "BLOCK",
      reasonCodes: [failure.reasonCode],
      approval: { mode: "policy_engine", approval_reference: null, approver_ids: [] },
    },
    policyHash: hashPolicyObject(organisationalPolicy),
    policyVersion: organisationalPolicy.policy_version,
    decisionTtlSeconds: 60,
    signer,
    clock,
    decisionId: input.decisionId,
    nonce: input.nonce,
  });
}

const overPresentation = await presentation({
  root,
  intermediary,
  agent,
  nonce: "AQIDBAUGBwgJCgsMDQ4PMQ",
  amount: "401.00",
  maxAmount: "400.00",
});
const wrongAgentPresentation = await presentation({
  root,
  intermediary,
  agent,
  nonce: "AQIDBAUGBwgJCgsMDQ4PMg",
});
const revokedPresentation = await presentation({
  root,
  intermediary,
  agent,
  nonce: "AQIDBAUGBwgJCgsMDQ4PMw",
});
const amountOverBlock = await blockEvidence({
  presentation: overPresentation,
  action: action(agent.did, root.did, "401.00"),
  decisionId: "018f0000-0000-7000-8000-000000000402",
  nonce: "a3lhLWV2aWRlbmNlLW92ZXI",
});
const wrongAgentBlock = await blockEvidence({
  presentation: wrongAgentPresentation,
  action: action(identity(45).did, root.did),
  decisionId: "018f0000-0000-7000-8000-000000000403",
  nonce: "a3lhLWV2aWRlbmNlLXdyb25n",
});
const revokedBlock = await blockEvidence({
  presentation: revokedPresentation,
  action: action(agent.did, root.did),
  revoked: true,
  decisionId: "018f0000-0000-7000-8000-000000000404",
  nonce: "a3lhLWV2aWRlbmNlLXJldm9rZWQ",
});
const didWebPresentation = await presentation({
  root,
  intermediary,
  agent: didWebAgent,
  nonce: "AQIDBAUGBwgJCgsMDQ4PNA",
});
const l3Presentation = await presentation({
  root,
  intermediary,
  agent,
  nonce: "AQIDBAUGBwgJCgsMDQ4PNQ",
  l3: true,
});

async function json(value: unknown): Promise<string> {
  return format(JSON.stringify(value), { parser: "json", printWidth: 100 });
}

async function writeJson(path: string, value: unknown): Promise<string> {
  const content = await json(value);
  await mkdir(resolve(path, ".."), { recursive: true });
  await writeFile(path, content, "utf8");
  return `sha256:${createHash("sha256").update(content).digest("hex")}`;
}

const evidenceDirectory = resolve("evidence/kya-os");
const fixtureDirectory = resolve("fixtures/kya-os");
const fixtureHashes: Record<string, string> = {};
fixtureHashes["delegation/valid-two-hop.json"] = await writeJson(
  resolve(fixtureDirectory, "delegation/valid-two-hop.json"),
  validPresentation.delegation_chain,
);
fixtureHashes["proofs/valid-did-key.json"] = await writeJson(
  resolve(fixtureDirectory, "proofs/valid-did-key.json"),
  validPresentation.request_proof,
);
fixtureHashes["presentations/valid-two-hop.json"] = await writeJson(
  resolve(fixtureDirectory, "presentations/valid-two-hop.json"),
  validPresentation,
);
fixtureHashes["presentations/valid-did-key.json"] = await writeJson(
  resolve(fixtureDirectory, "presentations/valid-did-key.json"),
  validPresentation,
);
fixtureHashes["presentations/valid-did-web.json"] = await writeJson(
  resolve(fixtureDirectory, "presentations/valid-did-web.json"),
  didWebPresentation,
);
fixtureHashes["entity-card/did-web-agent-document.json"] = await writeJson(
  resolve(fixtureDirectory, "entity-card/did-web-agent-document.json"),
  {
    id: didWebAgent.did,
    verificationMethod: [
      {
        id: didWebAgent.kid,
        type: "JsonWebKey2020",
        controller: didWebAgent.did,
        publicKeyJwk: didWebAgent.publicJwk,
      },
    ],
    authentication: [didWebAgent.kid],
    assertionMethod: [didWebAgent.kid],
  },
);
fixtureHashes["presentations/valid-l3-minus.json"] = await writeJson(
  resolve(fixtureDirectory, "presentations/valid-l3-minus.json"),
  validPresentation,
);
fixtureHashes["presentations/valid-l3.json"] = await writeJson(
  resolve(fixtureDirectory, "presentations/valid-l3.json"),
  l3Presentation,
);
fixtureHashes["entity-card/test-only-identities.json"] = await writeJson(
  resolve(fixtureDirectory, "entity-card/test-only-identities.json"),
  {
    warning: "TEST ONLY public identities. Private derivation bytes are fixed in the generator.",
    root: { did: root.did, kid: root.kid },
    intermediary: { did: intermediary.did, kid: intermediary.kid },
    agent: { did: agent.did, kid: agent.kid },
    did_web_agent: { did: didWebAgent.did, kid: didWebAgent.kid },
  },
);

const negativeReasons: Record<string, string> = {
  "bad-proof-signature": "KYA_PROOF_INVALID",
  "bad-delegation-signature": "KYA_DELEGATION_SIGNATURE_INVALID",
  "mutated-credential-after-signing": "KYA_DELEGATION_SIGNATURE_INVALID",
  "kid-did-mismatch": "KYA_AGENT_IDENTITY_MISMATCH",
  "kid-not-in-did-document": "KYA_AGENT_IDENTITY_MISMATCH",
  "wrong-audience": "KYA_AUDIENCE_MISMATCH",
  "request-hash-mismatch": "KYA_PROOF_INVALID",
  "proof-expired": "KYA_PROOF_INVALID",
  "proof-created-in-future": "KYA_PROOF_INVALID",
  "proof-ttl-too-long": "KYA_PROOF_INVALID",
  "proof-replay": "KYA_PROOF_REPLAYED",
  "empty-chain": "KYA_DELEGATION_INVALID",
  "chain-depth-11": "KYA_DELEGATION_INVALID",
  "action-escalation": "KYA_DELEGATION_INVALID",
  "max-amount-broadened": "KYA_DELEGATION_INVALID",
  "max-amount-dropped": "KYA_DELEGATION_INVALID",
  "valid-until-broadened": "KYA_DELEGATION_INVALID",
  "currency-switched": "KYA_DELEGATION_INVALID",
  "broken-issuer-invoker-continuity": "KYA_DELEGATION_INVALID",
  "broken-parent-capability": "KYA_DELEGATION_INVALID",
  "invocation-target-drift": "KYA_INVOCATION_TARGET_MISMATCH",
  "root-resource-mismatch": "KYA_INVOCATION_TARGET_MISMATCH",
  "delegation-expired": "KYA_DELEGATION_EXPIRED",
  "delegation-not-yet-valid": "KYA_DELEGATION_EXPIRED",
  "delegation-revoked": "KYA_DELEGATION_REVOKED",
  "status-unresolvable": "KYA_REVOCATION_UNAVAILABLE",
  "status-stale": "KYA_REVOCATION_UNAVAILABLE",
  "leaf-invoker-proof-did-mismatch": "KYA_AGENT_IDENTITY_MISMATCH",
  "responsible-party-not-allowed": "KYA_RESPONSIBLE_PARTY_NOT_ALLOWED",
  "action-not-delegated": "KYA_ACTION_NOT_DELEGATED",
  "max-amount-missing": "KYA_MAX_AMOUNT_REQUIRED",
  "amount-over-max": "KYA_AMOUNT_EXCEEDS_DELEGATION",
  "amount-equal-max": "ALLOW",
  "currency-mismatch": "KYA_CURRENCY_MISMATCH",
  "resource-mismatch": "KYA_INVOCATION_TARGET_MISMATCH",
  "payee-mismatch": "KYA_AUTHORITY_BINDING_MISMATCH",
  "spoofed-inntris-kya-extension": "KYA_AUTHORITY_BINDING_MISMATCH",
};
for (const [name, expectedReasonCode] of Object.entries(negativeReasons)) {
  fixtureHashes[`presentations/${name}.json`] = await writeJson(
    resolve(fixtureDirectory, `presentations/${name}.json`),
    {
      version: "inntris-kya-mutation-vector-v1",
      base: "valid-two-hop.json",
      mutation: name,
      expected_reason_code: expectedReasonCode,
    },
  );
}

await writeJson(resolve(evidenceDirectory, "authority-policy.json"), authorityPolicy);
await writeJson(resolve(evidenceDirectory, "valid-presentation.json"), validPresentation);
await writeJson(resolve(evidenceDirectory, "verified-authority-binding.json"), verified.binding);
await writeJson(resolve(evidenceDirectory, "inntris-action.json"), boundAction);
await writeJson(resolve(evidenceDirectory, "signed-allow.json"), allow);
await writeJson(resolve(evidenceDirectory, "amount-over-delegation-block.json"), amountOverBlock);
await writeJson(resolve(evidenceDirectory, "wrong-agent-block.json"), wrongAgentBlock);
await writeJson(resolve(evidenceDirectory, "revoked-delegation-block.json"), revokedBlock);
await writeJson(resolve(evidenceDirectory, "manifest.json"), {
  release_target: "v0.4.0",
  protocol_version: "1.0.0",
  kya_package: { name: "@kya-os/mcp", version: "1.12.0" },
  dependencies: {
    "@digitalbazaar/eddsa-jcs-2022-cryptosuite": "1.0.0",
    "@digitalbazaar/ed25519-multikey": "1.3.0",
    "base58-universal": "2.0.0",
  },
  fixture_hashes: fixtureHashes,
  authority_policy_hash: hashKyaAuthorityPolicy(authorityPolicy),
  expected_action_hash: allow.action_hash,
  expected_authority_hash: verified.binding.authority_hash,
  expected_decision_fingerprint: allow.decision_fingerprint,
  reproduction_command: "pnpm evidence:kya:generate && pnpm evidence:kya:verify",
});
await mkdir(evidenceDirectory, { recursive: true });
await writeFile(
  resolve(evidenceDirectory, "reproduction.txt"),
  "pnpm install --frozen-lockfile\npnpm evidence:kya:generate\npnpm evidence:kya:verify\n",
  "utf8",
);

process.stdout.write("Generated deterministic KYA authority fixtures and evidence\n");
