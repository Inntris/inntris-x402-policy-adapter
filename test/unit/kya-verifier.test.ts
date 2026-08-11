import { describe, expect, it } from "vitest";

import {
  DefaultKyaAuthorityVerifier,
  InMemoryKyaNonceStore,
  ModernKyaDelegationVerifier,
  OfficialEddsaJcs2022Verifier,
  ProductionKyaDidResolver,
  UpstreamKyaRequestProofVerifier,
} from "@inntris/kya-os-authority";

import { MutableClock } from "../helpers.js";
import {
  buildKyaFixture,
  deterministicDidKey,
  KYA_AUDIENCE,
  KYA_NOW,
  signDelegationCredential,
} from "../kya-helpers.js";

function verifier(clock = new MutableClock(KYA_NOW)): DefaultKyaAuthorityVerifier {
  const resolver = new ProductionKyaDidResolver();
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

describe("KYA authority verifier", () => {
  it("binds verified authority to the exact Inntris financial action", async () => {
    const fixture = await buildKyaFixture();
    const result = await verifier().verify({
      presentation: fixture.presentation,
      action: fixture.action,
      authorityPolicy: fixture.policy,
      expectedAudience: KYA_AUDIENCE,
      now: KYA_NOW,
    });
    expect(result.agentDid).toBe(fixture.agent.did);
    expect(result.responsiblePartyDid).toBe(fixture.root.did);
    expect(result.binding.status).toBe("verified");
    expect(result.binding.max_amount).toBe("500.00");
  });

  it("rejects an amount above delegated MaxAmount", async () => {
    const fixture = await buildKyaFixture({ amount: "501.00", maxAmount: "500.00" });
    await expect(
      verifier().verify({
        presentation: fixture.presentation,
        action: fixture.action,
        authorityPolicy: fixture.policy,
        expectedAudience: KYA_AUDIENCE,
        now: KYA_NOW,
      }),
    ).rejects.toMatchObject({ reasonCode: "KYA_AMOUNT_EXCEEDS_DELEGATION" });
  });

  it("rejects a spoofed reserved extension", async () => {
    const fixture = await buildKyaFixture();
    await expect(
      verifier().verify({
        presentation: fixture.presentation,
        action: { ...fixture.action, extensions: { "org.inntris/kya-os": { status: "verified" } } },
        authorityPolicy: fixture.policy,
        expectedAudience: KYA_AUDIENCE,
        now: KYA_NOW,
      }),
    ).rejects.toMatchObject({ reasonCode: "KYA_AUTHORITY_BINDING_MISMATCH" });
  });

  it("allows an amount exactly equal to delegated MaxAmount", async () => {
    const fixture = await buildKyaFixture({
      amount: "500.00",
      maxAmount: "500.00",
      nonce: "AQIDBAUGBwgJCgsMDQ4PMQ",
    });
    await expect(
      verifier().verify({
        presentation: fixture.presentation,
        action: fixture.action,
        authorityPolicy: fixture.policy,
        expectedAudience: KYA_AUDIENCE,
        now: KYA_NOW,
      }),
    ).resolves.toMatchObject({ maxAmount: "500.00" });
  });

  it("rejects leaf identity, Responsible Party and action scope mismatches", async () => {
    const leaf = await buildKyaFixture({ nonce: "AQIDBAUGBwgJCgsMDQ4PMg" });
    const leafUnsigned = structuredClone(leaf.delegation);
    delete leafUnsigned.proof;
    (leafUnsigned.credentialSubject as Record<string, unknown>).invoker =
      deterministicDidKey(55).did;
    const leafPresentation = {
      ...leaf.presentation,
      delegation_chain: [await signDelegationCredential(leafUnsigned, leaf.root)],
    };
    await expect(
      verifier().verify({
        presentation: leafPresentation,
        action: leaf.action,
        authorityPolicy: leaf.policy,
        expectedAudience: KYA_AUDIENCE,
        now: KYA_NOW,
      }),
    ).rejects.toMatchObject({ reasonCode: "KYA_AGENT_IDENTITY_MISMATCH" });

    const responsible = await buildKyaFixture({ nonce: "AQIDBAUGBwgJCgsMDQ4PMw" });
    await expect(
      verifier().verify({
        presentation: responsible.presentation,
        action: responsible.action,
        authorityPolicy: {
          ...responsible.policy,
          responsible_parties: [deterministicDidKey(56).did],
        },
        expectedAudience: KYA_AUDIENCE,
        now: KYA_NOW,
      }),
    ).rejects.toMatchObject({ reasonCode: "KYA_RESPONSIBLE_PARTY_NOT_ALLOWED" });

    const scope = await buildKyaFixture({ nonce: "AQIDBAUGBwgJCgsMDQ4PNA" });
    const scopeUnsigned = structuredClone(scope.delegation);
    delete scopeUnsigned.proof;
    (scopeUnsigned.credentialSubject as Record<string, unknown>).allowedAction = ["payments.quote"];
    await expect(
      verifier().verify({
        presentation: {
          ...scope.presentation,
          delegation_chain: [await signDelegationCredential(scopeUnsigned, scope.root)],
        },
        action: scope.action,
        authorityPolicy: scope.policy,
        expectedAudience: KYA_AUDIENCE,
        now: KYA_NOW,
      }),
    ).rejects.toMatchObject({ reasonCode: "KYA_ACTION_NOT_DELEGATED" });
  });

  it("rejects missing MaxAmount and insufficient proof assurance", async () => {
    const missing = await buildKyaFixture({ nonce: "AQIDBAUGBwgJCgsMDQ4PNQ" });
    const unsigned = structuredClone(missing.delegation);
    delete unsigned.proof;
    const subject = unsigned.credentialSubject as {
      caveats?: { type?: string }[];
    };
    subject.caveats = subject.caveats?.filter((caveat) => caveat.type !== "MaxAmount");
    await expect(
      verifier().verify({
        presentation: {
          ...missing.presentation,
          delegation_chain: [await signDelegationCredential(unsigned, missing.root)],
        },
        action: missing.action,
        authorityPolicy: missing.policy,
        expectedAudience: KYA_AUDIENCE,
        now: KYA_NOW,
      }),
    ).rejects.toMatchObject({ reasonCode: "KYA_MAX_AMOUNT_REQUIRED" });

    const assurance = await buildKyaFixture({ nonce: "AQIDBAUGBwgJCgsMDQ4PNg" });
    await expect(
      verifier().verify({
        presentation: assurance.presentation,
        action: assurance.action,
        authorityPolicy: { ...assurance.policy, min_proof_assurance: "L3" },
        expectedAudience: KYA_AUDIENCE,
        now: KYA_NOW,
      }),
    ).rejects.toMatchObject({ reasonCode: "KYA_PROOF_ASSURANCE_INSUFFICIENT" });
  });

  it("rejects exact amount, payee, resource and currency join failures", async () => {
    const cases = [
      {
        fixture: await buildKyaFixture({ nonce: "AQIDBAUGBwgJCgsMDQ4PNw" }),
        action: (base: Awaited<ReturnType<typeof buildKyaFixture>>["action"]) => ({
          ...base,
          transaction: { ...base.transaction, amount: "43.00" },
        }),
        reasonCode: "KYA_AUTHORITY_BINDING_MISMATCH",
      },
      {
        fixture: await buildKyaFixture({ nonce: "AQIDBAUGBwgJCgsMDQ4POA" }),
        action: (base: Awaited<ReturnType<typeof buildKyaFixture>>["action"]) => ({
          ...base,
          transaction: { ...base.transaction, payee: "did:web:other.example" },
        }),
        reasonCode: "KYA_AUTHORITY_BINDING_MISMATCH",
      },
      {
        fixture: await buildKyaFixture({ nonce: "AQIDBAUGBwgJCgsMDQ4POQ" }),
        action: (base: Awaited<ReturnType<typeof buildKyaFixture>>["action"]) => ({
          ...base,
          protocol_reference: {
            ...base.protocol_reference,
            resource: "https://other.example/api/data",
          },
        }),
        reasonCode: "KYA_INVOCATION_TARGET_MISMATCH",
      },
      {
        fixture: await buildKyaFixture({ nonce: "AQIDBAUGBwgJCgsMDQ4POg" }),
        action: (base: Awaited<ReturnType<typeof buildKyaFixture>>["action"]) => ({
          ...base,
          transaction: { ...base.transaction, asset: "EUR" },
        }),
        reasonCode: "KYA_CURRENCY_MISMATCH",
      },
    ];
    for (const item of cases) {
      await expect(
        verifier().verify({
          presentation: item.fixture.presentation,
          action: item.action(item.fixture.action),
          authorityPolicy: item.fixture.policy,
          expectedAudience: KYA_AUDIENCE,
          now: KYA_NOW,
        }),
      ).rejects.toMatchObject({ reasonCode: item.reasonCode });
    }
  });
});
