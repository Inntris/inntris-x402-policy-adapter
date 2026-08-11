import { sign as signBytes } from "node:crypto";

import {
  DefaultKyaAuthorityVerifier,
  InMemoryKyaNonceStore,
  ProductionKyaDidResolver,
  UpstreamKyaRequestProofVerifier,
  UpstreamLegacyKyaVerificationAdapter,
} from "@inntris/kya-os-authority";
import { canonicalizeJSON } from "@kya-os/mcp/delegation";
import { describe, expect, it } from "vitest";

import { MutableClock } from "../helpers.js";
import { buildKyaFixture, KYA_AUDIENCE, KYA_NOW, KYA_TARGET } from "../kya-helpers.js";

async function legacyFixture(nonce: string) {
  const fixture = await buildKyaFixture({ nonce });
  const unsigned = {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://schema.kya-os.org/v1/protocol/delegation/context/v1.0.0",
    ],
    id: "urn:uuid:00000000-0000-4000-8000-000000000099",
    type: ["VerifiableCredential", "DelegationCredential"],
    issuer: fixture.root.did,
    issuanceDate: "2026-01-01T00:00:00.000Z",
    expirationDate: "2030-01-01T00:00:00.000Z",
    credentialSubject: {
      id: fixture.agent.did,
      delegation: {
        id: "legacy-payment-authority",
        issuerDid: fixture.root.did,
        subjectDid: fixture.agent.did,
        constraints: {
          scopes: ["payments.transfer"],
          audience: KYA_AUDIENCE,
          notBefore: Math.floor(new Date("2026-01-01T00:00:00.000Z").getTime() / 1_000),
          notAfter: Math.floor(new Date("2030-01-01T00:00:00.000Z").getTime() / 1_000),
          invocationTarget: KYA_TARGET,
          maxAmount: "500.00",
          currency: "USD",
        },
        status: "active",
      },
    },
  };
  const signature = signBytes(
    null,
    Buffer.from(canonicalizeJSON(unsigned), "utf8"),
    fixture.root.privateKey,
  ).toString("base64url");
  const credential = {
    ...unsigned,
    proof: {
      type: "Ed25519Signature2020",
      created: KYA_NOW.toISOString(),
      verificationMethod: fixture.root.kid,
      proofPurpose: "assertionMethod",
      proofValue: signature,
    },
  };
  return {
    ...fixture,
    policy: {
      ...fixture.policy,
      profiles: ["legacy-v1" as const],
      require_fresh_revocation: false,
    },
    presentation: {
      profile: "legacy-v1" as const,
      request: fixture.presentation.request,
      credential,
      audience: KYA_AUDIENCE,
      proof: fixture.presentation.request_proof,
    },
  };
}

function verifier() {
  const clock = new MutableClock(KYA_NOW);
  const resolver = new ProductionKyaDidResolver();
  const requestProof = new UpstreamKyaRequestProofVerifier({
    resolver,
    nonceStore: new InMemoryKyaNonceStore(),
    clock,
  });
  return new DefaultKyaAuthorityVerifier({
    requestProof,
    delegation: { verify: async () => Promise.reject(new Error("modern path not expected")) },
    legacy: new UpstreamLegacyKyaVerificationAdapter({
      resolver,
      requestProof,
      revocation: async () => ({ revoked: false, fresh: true }),
    }),
  });
}

describe("legacy KYA authority compatibility", () => {
  it("verifies an upstream legacy DelegationCredential and live request proof", async () => {
    const fixture = await legacyFixture("AQIDBAUGBwgJCgsMDQ4PGQ");
    const result = await verifier().verify({
      presentation: fixture.presentation,
      action: fixture.action,
      authorityPolicy: fixture.policy,
      expectedAudience: KYA_AUDIENCE,
      now: KYA_NOW,
    });
    expect(result.binding).toMatchObject({
      status: "verified",
      profile: "legacy-v1",
      agent_did: fixture.agent.did,
      responsible_party_did: fixture.root.did,
      max_amount: "500.00",
    });
  });

  it("rejects a bad legacy credential signature", async () => {
    const fixture = await legacyFixture("AQIDBAUGBwgJCgsMDQ4PGg");
    const credential = structuredClone(fixture.presentation.credential) as Record<string, unknown>;
    const proof = credential.proof as Record<string, unknown>;
    proof.proofValue = `${String(proof.proofValue).slice(0, -2)}AA`;
    await expect(
      verifier().verify({
        presentation: { ...fixture.presentation, credential },
        action: fixture.action,
        authorityPolicy: fixture.policy,
        expectedAudience: KYA_AUDIENCE,
        now: KYA_NOW,
      }),
    ).rejects.toMatchObject({ reasonCode: "KYA_DELEGATION_SIGNATURE_INVALID" });
  });

  it("rejects a mismatched signed legacy audience", async () => {
    const fixture = await legacyFixture("AQIDBAUGBwgJCgsMDQ4PGw");
    await expect(
      verifier().verify({
        presentation: { ...fixture.presentation, audience: "did:web:wrong.example" },
        action: fixture.action,
        authorityPolicy: fixture.policy,
        expectedAudience: "did:web:wrong.example",
        now: KYA_NOW,
      }),
    ).rejects.toMatchObject({ reasonCode: "KYA_AUDIENCE_MISMATCH" });
  });
});
