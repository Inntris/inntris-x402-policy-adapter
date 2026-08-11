import { buildDemoApi } from "../../apps/demo-api/src/app.js";

import {
  buildKeyRegistryEntry,
  createPublicDemoSigner,
  type KeyRegistry,
} from "@inntris/decision-core";
import {
  DefaultKyaAuthorityVerifier,
  hashKyaAuthorityPolicy,
  InMemoryKyaAuthorityStateStore,
  InMemoryKyaNonceStore,
  KyaAuthorityGate,
  ModernKyaDelegationVerifier,
  OfficialEddsaJcs2022Verifier,
  ProductionKyaDidResolver,
  UpstreamKyaRequestProofVerifier,
} from "@inntris/kya-os-authority";
import { LocalPolicyDecisionProvider, type InntrisPolicyV1 } from "@inntris/policy-engine";
import { describe, expect, it } from "vitest";

import { MutableClock } from "../helpers.js";
import { buildKyaFixture, INNTRIS_RESOURCE, KYA_NOW } from "../kya-helpers.js";

const ADDRESS = "0x0000000000000000000000000000000000000001";

function organisationalPolicy(payee: string): InntrisPolicyV1 {
  return {
    version: 1,
    policy_id: "kya-api-policy",
    policy_version: "1",
    defaults: { verdict: "BLOCK", decision_ttl_seconds: 60 },
    rails: { x402: { allowed_networks: ["eip155:8453"], allowed_assets: ["USDC"] } },
    limits: { per_transaction: "100.00", daily: "500.00" },
    approval: { require_human_above: "75.00" },
    merchants: [
      {
        merchant_id: "kya-api-merchant",
        payees: [payee],
        purposes: ["research_api"],
        resources: [INNTRIS_RESOURCE],
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
}

async function context(options: { amount?: string; nonce?: string } = {}) {
  const fixture = await buildKyaFixture({
    nonce: options.nonce ?? "AQIDBAUGBwgJCgsMDQ4PHA",
    ...(options.amount === undefined ? {} : { amount: options.amount }),
    payee: ADDRESS,
  });
  const clock = new MutableClock(KYA_NOW);
  const signer = createPublicDemoSigner();
  const provider = new LocalPolicyDecisionProvider({
    policy: organisationalPolicy(ADDRESS),
    signer,
    clock,
  });
  const resolver = new ProductionKyaDidResolver();
  const requestProof = new UpstreamKyaRequestProofVerifier({
    resolver,
    nonceStore: new InMemoryKyaNonceStore(),
    clock,
  });
  const gate = new KyaAuthorityGate({
    provider,
    authorityPolicy: fixture.policy,
    stateStore: new InMemoryKyaAuthorityStateStore(),
    clock,
    verifier: new DefaultKyaAuthorityVerifier({
      requestProof,
      delegation: new ModernKyaDelegationVerifier({
        signatures: new OfficialEddsaJcs2022Verifier(resolver),
        revocation: async () => ({ revoked: false, fresh: true }),
      }),
    }),
  });
  const keyRegistry: KeyRegistry = {
    version: "inntris-key-registry-v1",
    keys: [buildKeyRegistryEntry(signer, { notBefore: new Date("2026-01-01T00:00:00.000Z") })],
  };
  const app = await buildDemoApi({
    provider,
    keyRegistry,
    clock,
    logger: false,
    kya: { mode: "required", policy: fixture.policy, gate },
  });
  return { app, fixture };
}

function evaluatePayload(
  presentation: Awaited<ReturnType<typeof buildKyaFixture>>["presentation"],
  amount = "42000000",
) {
  return {
    payment_requirements: {
      scheme: "exact",
      network: "eip155:8453",
      asset: "USDC",
      amount,
      payTo: ADDRESS,
      maxTimeoutSeconds: 60,
      extra: {},
    },
    resource: INNTRIS_RESOURCE,
    purpose: "research_api",
    asset_decimals: 6,
    presentation,
  };
}

describe("KYA reference API", () => {
  it("exposes only non-secret KYA policy configuration", async () => {
    const { app, fixture } = await context();
    const response = await app.inject({ method: "GET", url: "/v1/kya/config" });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      enabled: true,
      mode: "required",
      authority_policy: {
        policy_id: fixture.policy.policy_id,
        policy_version: fixture.policy.policy_version,
        policy_hash: hashKyaAuthorityPolicy(fixture.policy),
        profiles: fixture.policy.profiles,
        accepted_did_methods: fixture.policy.accepted_did_methods,
        min_proof_assurance: fixture.policy.min_proof_assurance,
        require_fresh_revocation: fixture.policy.require_fresh_revocation,
      },
    });
    expect(response.body).not.toContain("private");
    await app.close();
  });

  it("derives identity from valid KYA authority and evaluates the exact x402 action", async () => {
    const { app, fixture } = await context();
    const response = await app.inject({
      method: "POST",
      url: "/v1/kya/x402/evaluate",
      payload: evaluatePayload(fixture.presentation),
    });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      decision: {
        verdict: "ALLOW",
        rail: "x402",
      },
    });
    await app.close();
  });

  it("blocks ordinary evaluation of a protected action when KYA is required", async () => {
    const { app, fixture } = await context();
    const response = await app.inject({
      method: "POST",
      url: "/v1/decisions/evaluate",
      payload: { action: fixture.action },
    });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      decision: { verdict: "BLOCK", reason_codes: ["KYA_AUTHORITY_REQUIRED"] },
    });
    await app.close();
  });

  it("rejects caller identity fields and the reserved KYA extension", async () => {
    const first = await context();
    const identity = await first.app.inject({
      method: "POST",
      url: "/v1/kya/x402/evaluate",
      payload: {
        ...evaluatePayload(first.fixture.presentation),
        agent_id: first.fixture.agent.did,
      },
    });
    expect(identity.statusCode).toBe(400);
    await first.app.close();

    const second = await context();
    const spoofed = await second.app.inject({
      method: "POST",
      url: "/v1/kya/x402/evaluate",
      payload: {
        ...evaluatePayload(second.fixture.presentation),
        extensions: { "org.inntris/kya-os": { status: "verified" } },
      },
    });
    expect(spoofed.statusCode).toBe(400);
    await second.app.close();
  });

  it("blocks ordinary consumption of a KYA protected decision", async () => {
    const { app, fixture } = await context({ nonce: "AQIDBAUGBwgJCgsMDQ4PHQ" });
    const evaluated = await app.inject({
      method: "POST",
      url: "/v1/kya/x402/evaluate",
      payload: evaluatePayload(fixture.presentation),
    });
    const decision = evaluated.json<{ decision: { decision_id: string; action_hash: string } }>()
      .decision;
    const response = await app.inject({
      method: "POST",
      url: "/v1/decisions/consume",
      payload: {
        decision_id: decision.decision_id,
        action_hash: decision.action_hash,
        execution_ref: "bypass-attempt",
      },
    });
    expect(response.statusCode).toBe(422);
    expect(response.json()).toMatchObject({ reason_code: "KYA_AUTHORITY_REQUIRED" });
    await app.close();
  });

  it("blocks ordinary approval of a KYA protected decision", async () => {
    const { app, fixture } = await context({
      amount: "80.00",
      nonce: "AQIDBAUGBwgJCgsMDQ4PHg",
    });
    const evaluated = await app.inject({
      method: "POST",
      url: "/v1/kya/x402/evaluate",
      payload: evaluatePayload(fixture.presentation, "80000000"),
    });
    expect(evaluated.json()).toMatchObject({ decision: { verdict: "REQUIRE_APPROVAL" } });
    const decision = evaluated.json<{ decision: { decision_id: string } }>().decision;
    const response = await app.inject({
      method: "POST",
      url: "/v1/decisions/approve",
      payload: {
        decision_id: decision.decision_id,
        granted: true,
        approval_reference: "bypass-attempt",
        approver_ids: ["reviewer-1"],
      },
    });
    expect(response.statusCode).toBe(422);
    expect(response.json()).toMatchObject({ reason_code: "KYA_AUTHORITY_REQUIRED" });
    await app.close();
  });

  it("requires fresh authority through the KYA approval and consumption endpoints", async () => {
    const { app, fixture } = await context({
      amount: "80.00",
      nonce: "AQIDBAUGBwgJCgsMDQ4PHw",
    });
    const evaluated = await app.inject({
      method: "POST",
      url: "/v1/kya/x402/evaluate",
      payload: evaluatePayload(fixture.presentation, "80000000"),
    });
    const pending = evaluated.json<{ decision: { decision_id: string; verdict: string } }>()
      .decision;
    expect(pending.verdict).toBe("REQUIRE_APPROVAL");

    const approvalAuthority = await buildKyaFixture({
      amount: "80.00",
      nonce: "AQIDBAUGBwgJCgsMDQ4PIA",
      payee: ADDRESS,
    });
    const approved = await app.inject({
      method: "POST",
      url: "/v1/kya/decisions/approve",
      payload: {
        decision_id: pending.decision_id,
        granted: true,
        approval_reference: "approval-1",
        approver_ids: ["reviewer-1"],
        presentation: approvalAuthority.presentation,
      },
    });
    expect(approved.statusCode).toBe(200);
    const decision = approved.json<{
      decision: { decision_id: string; action_hash: string; verdict: string };
    }>().decision;
    expect(decision.verdict).toBe("ALLOW");

    const consumptionAuthority = await buildKyaFixture({
      amount: "80.00",
      nonce: "AQIDBAUGBwgJCgsMDQ4PIQ",
      payee: ADDRESS,
    });
    const consumed = await app.inject({
      method: "POST",
      url: "/v1/kya/decisions/consume",
      payload: {
        decision_id: decision.decision_id,
        action_hash: decision.action_hash,
        execution_ref: "x402-payment-1",
        presentation: consumptionAuthority.presentation,
      },
    });
    expect(consumed.statusCode).toBe(200);
    expect(consumed.json()).toMatchObject({ success: true, status: "consumed" });
    await app.close();
  });
});
