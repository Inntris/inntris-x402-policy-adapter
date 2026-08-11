import { readFile } from "node:fs/promises";

import {
  KyaAuthorityPresentationSchema,
  ModernKyaDelegationVerifier,
  OfficialEddsaJcs2022Verifier,
  ProductionKyaDidResolver,
} from "@inntris/kya-os-authority";
import { validateDelegationChain, type DelegationCredential } from "@kya-os/mcp/card";
import { describe, expect, it } from "vitest";

import {
  buildKyaFixture,
  deterministicDidKey,
  KYA_NOW,
  KYA_TARGET,
  signDelegationCredential,
} from "../kya-helpers.js";

function chain(): [DelegationCredential, DelegationCredential] {
  const root = deterministicDidKey(31);
  const intermediary = deterministicDidKey(32);
  const agent = deterministicDidKey(33);
  const parentExpiry = new Date(KYA_NOW.getTime() + 300_000).toISOString();
  const childExpiry = new Date(KYA_NOW.getTime() + 240_000).toISOString();
  const parent = {
    "@context": [
      "https://www.w3.org/ns/credentials/v2",
      "https://w3id.org/security/zcap/v1",
      "https://kya-os.org/ns/delegation/v1",
    ],
    id: "urn:uuid:00000000-0000-4000-8000-000000000031",
    type: ["VerifiableCredential", "DelegationCredential"],
    issuer: root.did,
    validFrom: new Date(KYA_NOW.getTime() - 60_000).toISOString(),
    validUntil: parentExpiry,
    credentialSubject: {
      id: "urn:zcap:parent",
      invoker: intermediary.did,
      parentCapability: KYA_TARGET,
      invocationTarget: KYA_TARGET,
      allowedAction: ["payments.transfer", "payments.quote"],
      caveats: [
        { type: "MaxAmount", limit: "500.00", currency: "USD" },
        { type: "ValidUntil", date: parentExpiry },
      ],
    },
  } as DelegationCredential;
  const child = {
    ...structuredClone(parent),
    id: "urn:uuid:00000000-0000-4000-8000-000000000032",
    issuer: intermediary.did,
    validUntil: childExpiry,
    credentialSubject: {
      id: "urn:zcap:child",
      invoker: agent.did,
      parentCapability: "urn:zcap:parent",
      invocationTarget: KYA_TARGET,
      allowedAction: ["payments.transfer"],
      caveats: [
        { type: "MaxAmount", limit: "400.00", currency: "USD" },
        { type: "ValidUntil", date: childExpiry },
      ],
    },
  } as DelegationCredential;
  return [parent, child];
}

function reasons(value: DelegationCredential[]) {
  return validateDelegationChain(value, {
    now: () => KYA_NOW.getTime(),
    maxDepth: 10,
    resource: KYA_TARGET,
  });
}

describe("KYA modern delegation attenuation", () => {
  it("accepts a valid two hop narrowing chain", () => {
    expect(reasons(chain())).toMatchObject({ ok: true, depth: 2 });
  });

  it.each([
    [
      "action escalation",
      (child: DelegationCredential) => {
        child.credentialSubject.allowedAction.push("wallet.sweep");
      },
    ],
    [
      "MaxAmount broadening",
      (child: DelegationCredential) => {
        child.credentialSubject.caveats![0]!.limit = "600.00";
      },
    ],
    [
      "MaxAmount drop",
      (child: DelegationCredential) => {
        child.credentialSubject.caveats = child.credentialSubject.caveats!.slice(1);
      },
    ],
    [
      "currency switch",
      (child: DelegationCredential) => {
        child.credentialSubject.caveats![0]!.currency = "EUR";
      },
    ],
    [
      "broken parent capability",
      (child: DelegationCredential) => {
        child.credentialSubject.parentCapability = "urn:zcap:wrong";
      },
    ],
    [
      "invocation target drift",
      (child: DelegationCredential) => {
        child.credentialSubject.invocationTarget = "did:web:api.example:other";
      },
    ],
    [
      "validUntil broadening",
      (child: DelegationCredential) => {
        child.validUntil = new Date(KYA_NOW.getTime() + 600_000).toISOString();
      },
    ],
  ])("rejects %s", (_name, mutate) => {
    const value = chain();
    mutate(value[1]);
    expect(reasons(value).ok).toBe(false);
  });

  it("rejects continuity failure, wrong root resource, expiry and excessive depth", () => {
    const continuity = chain();
    continuity[1].issuer = deterministicDidKey(34).did;
    expect(reasons(continuity).ok).toBe(false);

    const wrongResource = validateDelegationChain(chain(), {
      now: () => KYA_NOW.getTime(),
      resource: "did:web:api.example:wrong",
    });
    expect(wrongResource.ok).toBe(false);

    const expired = chain();
    expired[0].validUntil = new Date(KYA_NOW.getTime() - 1).toISOString();
    expect(reasons(expired).ok).toBe(false);

    const repeated = Array.from({ length: 11 }, () => chain()[0]);
    expect(reasons(repeated).reasons.some((reason) => reason.includes("depth"))).toBe(true);
  });

  it("verifies every signature in a genuine two hop chain", async () => {
    const presentation = KyaAuthorityPresentationSchema.parse(
      JSON.parse(
        await readFile("fixtures/kya-os/presentations/valid-two-hop.json", "utf8"),
      ) as unknown,
    );
    if (presentation.profile !== "entity-card-v1") throw new TypeError("Expected modern fixture");
    const proof = presentation.request_proof as {
      did: string;
      kid: string;
      audience: string;
      nonce: string;
      created: number;
      expires: number;
    };
    const resolver = new ProductionKyaDidResolver();
    const fixture = await buildKyaFixture();
    const result = await new ModernKyaDelegationVerifier({
      signatures: new OfficialEddsaJcs2022Verifier(resolver),
      revocation: async () => ({ revoked: false, fresh: true }),
    }).verify({
      presentation,
      proof: {
        ...proof,
        assurance: "L3-minus",
        requestHash: `sha256:${"a".repeat(64)}`,
        proofHash: `sha256:${"b".repeat(64)}`,
      },
      policy: fixture.policy,
      now: KYA_NOW,
    });
    expect(result).toMatchObject({ delegationDepth: 2, revocationFresh: true });
  });

  it("distinguishes live revocation from stale or missing status", async () => {
    const fixture = await buildKyaFixture({ nonce: "AQIDBAUGBwgJCgsMDQ4PMA" });
    const proof = {
      did: fixture.agent.did,
      kid: fixture.agent.kid,
      assurance: "L3-minus" as const,
      audience: "did:web:inntris.example:verifier",
      requestHash: `sha256:${"a".repeat(64)}`,
      nonce: "AQIDBAUGBwgJCgsMDQ4PMA",
      created: Math.floor(KYA_NOW.getTime() / 1_000),
      expires: Math.floor(KYA_NOW.getTime() / 1_000) + 60,
      proofHash: `sha256:${"b".repeat(64)}`,
    };
    const resolver = new ProductionKyaDidResolver();
    const verifier = (revoked: boolean, fresh: boolean) =>
      new ModernKyaDelegationVerifier({
        signatures: new OfficialEddsaJcs2022Verifier(resolver),
        revocation: async () => ({ revoked, fresh }),
      });
    await expect(
      verifier(true, true).verify({
        presentation: fixture.presentation,
        proof,
        policy: fixture.policy,
        now: KYA_NOW,
      }),
    ).rejects.toMatchObject({ reasonCode: "KYA_DELEGATION_REVOKED" });
    await expect(
      verifier(false, false).verify({
        presentation: fixture.presentation,
        proof,
        policy: fixture.policy,
        now: KYA_NOW,
      }),
    ).rejects.toMatchObject({ reasonCode: "KYA_REVOCATION_UNAVAILABLE" });

    const unsigned = structuredClone(fixture.delegation);
    delete unsigned.proof;
    delete unsigned.credentialStatus;
    const noStatus = await signDelegationCredential(unsigned, fixture.root);
    await expect(
      verifier(false, true).verify({
        presentation: { ...fixture.presentation, delegation_chain: [noStatus] },
        proof,
        policy: fixture.policy,
        now: KYA_NOW,
      }),
    ).rejects.toMatchObject({ reasonCode: "KYA_REVOCATION_UNAVAILABLE" });
  });
});
