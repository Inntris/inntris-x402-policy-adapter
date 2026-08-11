import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

import {
  InMemoryKyaNonceStore,
  KyaAuthorityPresentationSchema,
  KyaPaymentRequestV1Schema,
  ProductionKyaDidResolver,
  UpstreamKyaRequestProofVerifier,
} from "@inntris/kya-os-authority";

import { MutableClock } from "../helpers.js";
import { buildKyaFixture, KYA_AUDIENCE, KYA_NOW } from "../kya-helpers.js";

describe("KYA request proof", () => {
  it("verifies DID membership, audience, request binding and signature", async () => {
    const fixture = await buildKyaFixture();
    const verifier = new UpstreamKyaRequestProofVerifier({
      resolver: new ProductionKyaDidResolver(),
      nonceStore: new InMemoryKyaNonceStore(),
      clock: new MutableClock(KYA_NOW),
    });
    const result = await verifier.verify({
      proof: fixture.presentation.request_proof,
      request: fixture.presentation.request,
      expectedAudience: KYA_AUDIENCE,
    });
    expect(result.did).toBe(fixture.agent.did);
    expect(result.assurance).toBe("L3-minus");
  });

  it("verifies a signed did:web proof against the resolved DID document", async () => {
    const presentation = KyaAuthorityPresentationSchema.parse(
      JSON.parse(
        await readFile("fixtures/kya-os/presentations/valid-did-web.json", "utf8"),
      ) as unknown,
    );
    const document = JSON.parse(
      await readFile("fixtures/kya-os/entity-card/did-web-agent-document.json", "utf8"),
    ) as unknown;
    const resolver = new ProductionKyaDidResolver({
      safeFetch: async (url) => {
        expect(url).toBe("https://agent.example/.well-known/did.json");
        return { ok: true, status: 200, json: async () => document };
      },
    });
    const verifier = new UpstreamKyaRequestProofVerifier({
      resolver,
      nonceStore: new InMemoryKyaNonceStore(),
      clock: new MutableClock(KYA_NOW),
    });
    await expect(
      verifier.verify({
        proof: presentation.profile === "entity-card-v1" ? presentation.request_proof : {},
        request: presentation.request,
        expectedAudience: KYA_AUDIENCE,
      }),
    ).resolves.toMatchObject({ did: "did:web:agent.example" });
  });

  it("fails closed on a wrong audience", async () => {
    const fixture = await buildKyaFixture();
    const verifier = new UpstreamKyaRequestProofVerifier({
      resolver: new ProductionKyaDidResolver(),
      nonceStore: new InMemoryKyaNonceStore(),
      clock: new MutableClock(KYA_NOW),
    });
    await expect(
      verifier.verify({
        proof: fixture.presentation.request_proof,
        request: fixture.presentation.request,
        expectedAudience: "did:web:wrong.example",
      }),
    ).rejects.toMatchObject({ reasonCode: "KYA_AUDIENCE_MISMATCH" });
  });

  it("rejects DID mismatch, unpublished keys and invalid signatures", async () => {
    const cases = [
      {
        fixture: await buildKyaFixture({ nonce: "AQIDBAUGBwgJCgsMDQ4PLQ" }),
        mutate: (proof: Record<string, unknown>) => {
          proof.did = "did:key:z6MkhUnrelatedProofDid";
        },
        reasonCode: "KYA_AGENT_IDENTITY_MISMATCH",
      },
      {
        fixture: await buildKyaFixture({ nonce: "AQIDBAUGBwgJCgsMDQ4PLg" }),
        mutate: (proof: Record<string, unknown>) => {
          proof.kid = `${String(proof.did)}#not-published`;
        },
        reasonCode: "KYA_AGENT_IDENTITY_MISMATCH",
      },
      {
        fixture: await buildKyaFixture({ nonce: "AQIDBAUGBwgJCgsMDQ4PLw" }),
        mutate: (proof: Record<string, unknown>) => {
          proof.jws = `${String(proof.jws).split(".").slice(0, 2).join(".")}.${"A".repeat(86)}`;
          proof.httpSig = "A".repeat(86);
        },
        reasonCode: "KYA_PROOF_INVALID",
      },
    ];
    for (const item of cases) {
      const proof = structuredClone(item.fixture.presentation.request_proof) as Record<
        string,
        unknown
      >;
      item.mutate(proof);
      const verifier = new UpstreamKyaRequestProofVerifier({
        resolver: new ProductionKyaDidResolver(),
        nonceStore: new InMemoryKyaNonceStore(),
        clock: new MutableClock(KYA_NOW),
      });
      await expect(
        verifier.verify({
          proof,
          request: item.fixture.presentation.request,
          expectedAudience: KYA_AUDIENCE,
        }),
      ).rejects.toMatchObject({ reasonCode: item.reasonCode });
    }
  });

  it("atomically permits one concurrent nonce consumer", async () => {
    const fixture = await buildKyaFixture();
    const verifier = new UpstreamKyaRequestProofVerifier({
      resolver: new ProductionKyaDidResolver(),
      nonceStore: new InMemoryKyaNonceStore(),
      clock: new MutableClock(KYA_NOW),
    });
    const results = await Promise.allSettled([
      verifier.verify({
        proof: fixture.presentation.request_proof,
        request: fixture.presentation.request,
        expectedAudience: KYA_AUDIENCE,
      }),
      verifier.verify({
        proof: fixture.presentation.request_proof,
        request: fixture.presentation.request,
        expectedAudience: KYA_AUDIENCE,
      }),
    ]);
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    const rejection = results.find((result) => result.status === "rejected");
    expect(rejection).toMatchObject({
      status: "rejected",
      reason: { reasonCode: "KYA_PROOF_REPLAYED" },
    });
  });

  it("rejects malformed, mutated, expired, future and overlong proofs", async () => {
    const cases = [
      {
        fixture: await buildKyaFixture({ nonce: "AQIDBAUGBwgJCgsMDQ4PJQ" }),
        proof: { malformed: true },
        clock: new MutableClock(KYA_NOW),
        requestMutation: false,
      },
      {
        fixture: await buildKyaFixture({ nonce: "AQIDBAUGBwgJCgsMDQ4PJg" }),
        clock: new MutableClock(KYA_NOW),
        requestMutation: true,
      },
      {
        fixture: await buildKyaFixture({ nonce: "AQIDBAUGBwgJCgsMDQ4PJw" }),
        clock: new MutableClock(new Date(KYA_NOW.getTime() + 120_000)),
        requestMutation: false,
      },
      {
        fixture: await buildKyaFixture({
          nonce: "AQIDBAUGBwgJCgsMDQ4PKA",
          now: new Date(KYA_NOW.getTime() + 120_000),
        }),
        clock: new MutableClock(KYA_NOW),
        requestMutation: false,
      },
      {
        fixture: await buildKyaFixture({ nonce: "AQIDBAUGBwgJCgsMDQ4PKQ" }),
        clock: new MutableClock(KYA_NOW),
        requestMutation: false,
        overlong: true,
      },
    ];
    for (const item of cases) {
      const request = KyaPaymentRequestV1Schema.parse(
        structuredClone(item.fixture.presentation.request),
      );
      if (item.requestMutation) request.params.arguments.amount = "43.00";
      const verifier = new UpstreamKyaRequestProofVerifier({
        resolver: new ProductionKyaDidResolver(),
        nonceStore: new InMemoryKyaNonceStore(),
        clock: item.clock,
      });
      const proof = structuredClone(item.proof ?? item.fixture.presentation.request_proof);
      if (item.overlong) {
        const record = proof as Record<string, unknown>;
        record.expires = Number(record.created) + 600;
      }
      await expect(
        verifier.verify({
          proof,
          request,
          expectedAudience: KYA_AUDIENCE,
        }),
      ).rejects.toMatchObject({ reasonCode: "KYA_PROOF_INVALID" });
    }
  });

  it("derives L3 only when the access token confirmation key matches", async () => {
    const matching = await buildKyaFixture({
      nonce: "AQIDBAUGBwgJCgsMDQ4PKg",
      tokenCnf: "matching",
    });
    const verifier = new UpstreamKyaRequestProofVerifier({
      resolver: new ProductionKyaDidResolver(),
      nonceStore: new InMemoryKyaNonceStore(),
      clock: new MutableClock(KYA_NOW),
    });
    await expect(
      verifier.verify({
        proof: matching.presentation.request_proof,
        request: matching.presentation.request,
        expectedAudience: KYA_AUDIENCE,
        tokenCnfJkt: matching.presentation.token_cnf_jkt,
      }),
    ).resolves.toMatchObject({ assurance: "L3" });

    const mismatched = await buildKyaFixture({
      nonce: "AQIDBAUGBwgJCgsMDQ4PKw",
      tokenCnf: "mismatched",
    });
    await expect(
      verifier.verify({
        proof: mismatched.presentation.request_proof,
        request: mismatched.presentation.request,
        expectedAudience: KYA_AUDIENCE,
        tokenCnfJkt: mismatched.presentation.token_cnf_jkt,
      }),
    ).rejects.toMatchObject({ reasonCode: "KYA_PROOF_INVALID" });
  });

  it("fails closed when the nonce seam is unavailable", async () => {
    const fixture = await buildKyaFixture({ nonce: "AQIDBAUGBwgJCgsMDQ4PLA" });
    const verifier = new UpstreamKyaRequestProofVerifier({
      resolver: new ProductionKyaDidResolver(),
      nonceStore: {
        durability: "durable",
        consume: async () => Promise.reject(new Error("nonce store unavailable")),
      },
      clock: new MutableClock(KYA_NOW),
    });
    await expect(
      verifier.verify({
        proof: fixture.presentation.request_proof,
        request: fixture.presentation.request,
        expectedAudience: KYA_AUDIENCE,
      }),
    ).rejects.toMatchObject({ reasonCode: "KYA_PROOF_INVALID" });
  });
});
