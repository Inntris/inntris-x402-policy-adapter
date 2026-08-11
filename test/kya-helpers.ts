import { createPrivateKey, createPublicKey, sign as signBytes } from "node:crypto";

import { createSignCryptosuite } from "@digitalbazaar/eddsa-jcs-2022-cryptosuite";
import type { InntrisActionV1 } from "@inntris/decision-core";
import { KYA_OS_CARD_PROOF_META_KEY, buildCardProof, ed25519SignerFromJwk } from "@kya-os/mcp/card";
import { didKeyFragment, generateDidKeyFromBytes } from "@kya-os/mcp";
import { encode } from "base58-universal";

import type {
  KyaAuthorityPolicyV1,
  KyaEntityCardAuthorityPresentation,
} from "@inntris/kya-os-authority";

const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

export const KYA_NOW = new Date("2026-08-11T10:00:00.000Z");
export const KYA_AUDIENCE = "did:web:inntris.example:verifier";
export const KYA_TARGET = "did:web:api.example:payments";
export const INNTRIS_RESOURCE = "https://merchant.example/api/data";
export const PAYEE = "did:web:merchant.example";

export interface DeterministicDidKey {
  did: string;
  kid: string;
  privateJwk: { kty: "OKP"; crv: "Ed25519"; x: string; d: string };
  privateKey: ReturnType<typeof createPrivateKey>;
}

export function deterministicDidKey(fill: number): DeterministicDidKey {
  const seed = Buffer.alloc(32, fill);
  const privateKey = createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]),
    format: "der",
    type: "pkcs8",
  });
  const privateJwk = privateKey.export({ format: "jwk" });
  if (
    privateJwk.kty !== "OKP" ||
    privateJwk.crv !== "Ed25519" ||
    privateJwk.x === undefined ||
    privateJwk.d === undefined
  ) {
    throw new TypeError("Unable to derive deterministic Ed25519 JWK");
  }
  const publicJwk = createPublicKey(privateKey).export({ format: "jwk" });
  if (publicJwk.x === undefined) throw new TypeError("Missing Ed25519 public key");
  const publicBytes = Buffer.from(publicJwk.x, "base64url");
  const did = generateDidKeyFromBytes(publicBytes);
  return {
    did,
    kid: `${did}#${didKeyFragment(did)}`,
    privateJwk: { kty: "OKP", crv: "Ed25519", x: privateJwk.x, d: privateJwk.d },
    privateKey,
  };
}

export async function signDelegationCredential(
  unsigned: Record<string, unknown>,
  issuer: DeterministicDidKey,
): Promise<Record<string, unknown>> {
  const proof: Record<string, unknown> = {
    type: "DataIntegrityProof",
    cryptosuite: "eddsa-jcs-2022",
    created: KYA_NOW.toISOString(),
    verificationMethod: issuer.kid,
    proofPurpose: "assertionMethod",
  };
  const suite = createSignCryptosuite();
  const data = await suite.createVerifyData({
    cryptosuite: suite,
    document: structuredClone(unsigned),
    proof,
  });
  const signature = signBytes(null, data, issuer.privateKey);
  return { ...unsigned, proof: { ...proof, proofValue: `z${encode(signature)}` } };
}

export async function buildKyaFixture(
  options: {
    nonce?: string;
    maxAmount?: string;
    amount?: string;
    audience?: string;
    payee?: string;
    now?: Date;
    ttlSec?: number;
    tokenCnf?: "matching" | "mismatched";
  } = {},
): Promise<{
  root: DeterministicDidKey;
  agent: DeterministicDidKey;
  action: InntrisActionV1;
  policy: KyaAuthorityPolicyV1;
  presentation: KyaEntityCardAuthorityPresentation;
  delegation: Record<string, unknown>;
}> {
  const now = options.now ?? KYA_NOW;
  const root = deterministicDidKey(7);
  const agent = deterministicDidKey(9);
  const amount = options.amount ?? "42.00";
  const payee = options.payee ?? PAYEE;
  const request = {
    method: "tools/call",
    params: {
      name: "payments.transfer",
      arguments: {
        to: payee,
        amount,
        currency: "USD",
        resource: KYA_TARGET,
      },
    },
  } as const;
  const signer = await ed25519SignerFromJwk({
    did: agent.did,
    kid: agent.kid,
    privateJwk: agent.privateJwk,
  });
  const signerJkt = signer.jkt;
  if (options.tokenCnf === "matching" && signerJkt === undefined) {
    throw new TypeError("KYA test signer did not expose a JWK thumbprint");
  }
  const proofEnvelope = await buildCardProof(request, signer, {
    audience: options.audience ?? KYA_AUDIENCE,
    nonce: options.nonce ?? "AQIDBAUGBwgJCgsMDQ4PEA",
    ttlSec: options.ttlSec ?? 60,
    now: () => now.getTime(),
  });
  const expires = new Date(now.getTime() + 300_000).toISOString();
  const maxAmount = options.maxAmount ?? "500.00";
  const unsignedDelegation = {
    "@context": [
      "https://www.w3.org/ns/credentials/v2",
      "https://w3id.org/security/zcap/v1",
      "https://kya-os.org/ns/delegation/v1",
    ],
    id: "urn:uuid:00000000-0000-4000-8000-000000000001",
    type: ["VerifiableCredential", "DelegationCredential"],
    issuer: root.did,
    validFrom: new Date(now.getTime() - 60_000).toISOString(),
    validUntil: expires,
    credentialSubject: {
      id: "urn:zcap:00000000-0000-4000-8000-000000000001",
      invoker: agent.did,
      parentCapability: KYA_TARGET,
      invocationTarget: KYA_TARGET,
      allowedAction: ["payments.transfer"],
      caveats: [
        { type: "MaxAmount", limit: maxAmount, currency: "USD" },
        { type: "ValidUntil", date: expires },
      ],
    },
    credentialStatus: {
      type: "BitstringStatusListEntry",
      statusPurpose: "revocation",
      statusListIndex: "7",
      statusListCredential: "https://status.example/kya/1",
    },
  };
  const delegation = await signDelegationCredential(unsignedDelegation, root);
  const action: InntrisActionV1 = {
    version: "inntris-action-v1",
    principal_id: root.did,
    agent_id: agent.did,
    action_type: "financial_transaction",
    rail: "x402",
    protocol_reference: {
      type: "x402",
      resource: INNTRIS_RESOURCE,
      scheme: "exact",
      payment_requirements_hash:
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
      payment_payload_hash: null,
    },
    transaction: {
      amount,
      asset: "USDC",
      network: "eip155:8453",
      payee,
      purpose: "research_api",
    },
  };
  const policy: KyaAuthorityPolicyV1 = {
    version: 1,
    policy_id: "demo-kya-authority",
    policy_version: "1",
    mode: "required",
    profiles: ["entity-card-v1"],
    expected_audiences: [KYA_AUDIENCE],
    accepted_did_methods: ["did:key", "did:web"],
    responsible_parties: [root.did],
    allowed_actions: ["payments.transfer"],
    min_proof_assurance: "L3-minus",
    require_fresh_revocation: true,
    require_max_amount: true,
    max_delegation_depth: 10,
    principal_source: "responsible_party",
    resource_bindings: [{ inntris_resource: INNTRIS_RESOURCE, kya_invocation_target: KYA_TARGET }],
    currency_bindings: [{ inntris_asset: "USDC", kya_currency: "USD" }],
  };
  return {
    root,
    agent,
    action,
    policy,
    presentation: {
      profile: "entity-card-v1",
      request,
      request_proof: proofEnvelope[KYA_OS_CARD_PROOF_META_KEY],
      delegation_chain: [delegation],
      ...(options.tokenCnf === undefined
        ? {}
        : {
            token_cnf_jkt: options.tokenCnf === "matching" ? signerJkt : `sha256-${"x".repeat(43)}`,
          }),
    },
    delegation,
  };
}
