import { describe, expect, it } from "vitest";

import { createPublicDemoSigner } from "@inntris/decision-core";
import {
  DefaultKyaAuthorityVerifier,
  InMemoryKyaAuthorityStateStore,
  InMemoryKyaMetrics,
  InMemoryKyaNonceStore,
  KyaAuthorityGate,
  ModernKyaDelegationVerifier,
  OfficialEddsaJcs2022Verifier,
  ProductionKyaDidResolver,
  UpstreamKyaRequestProofVerifier,
  type KyaAuthorityStateStore,
  type KyaMetricsRecorder,
} from "@inntris/kya-os-authority";
import type { RevocationChecker } from "@kya-os/mcp/card";
import { LocalPolicyDecisionProvider, type InntrisPolicyV1 } from "@inntris/policy-engine";

import { MutableClock } from "../helpers.js";
import { buildKyaFixture, INNTRIS_RESOURCE, KYA_NOW, PAYEE } from "../kya-helpers.js";

function basePolicy(
  input: { transactionLimit?: string; approvalAbove?: string } = {},
): InntrisPolicyV1 {
  return {
    version: 1,
    policy_id: "kya-gate-base-policy",
    policy_version: "1",
    defaults: { verdict: "BLOCK", decision_ttl_seconds: 60 },
    rails: {
      x402: { allowed_networks: ["eip155:8453"], allowed_assets: ["USDC"] },
    },
    limits: {
      per_transaction: input.transactionLimit ?? "100.00",
      daily: "500.00",
    },
    approval: { require_human_above: input.approvalAbove ?? "75.00" },
    merchants: [
      {
        merchant_id: "kya-merchant",
        payees: [PAYEE],
        purposes: ["research_api"],
        resources: [INNTRIS_RESOURCE],
        per_transaction_limit: input.transactionLimit ?? "100.00",
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

async function gate(input: {
  fixture: Awaited<ReturnType<typeof buildKyaFixture>>;
  policy?: InntrisPolicyV1;
  clock?: MutableClock;
  stateStore?: KyaAuthorityStateStore;
  revocation?: RevocationChecker;
  metrics?: KyaMetricsRecorder;
}): Promise<KyaAuthorityGate> {
  const clock = input.clock ?? new MutableClock(KYA_NOW);
  const resolver = new ProductionKyaDidResolver();
  const provider = new LocalPolicyDecisionProvider({
    policy: input.policy ?? basePolicy(),
    signer: createPublicDemoSigner(),
    clock,
  });
  return new KyaAuthorityGate({
    provider,
    authorityPolicy: input.fixture.policy,
    stateStore: input.stateStore ?? new InMemoryKyaAuthorityStateStore(),
    clock,
    ...(input.metrics === undefined ? {} : { metrics: input.metrics }),
    verifier: new DefaultKyaAuthorityVerifier({
      requestProof: new UpstreamKyaRequestProofVerifier({
        resolver,
        nonceStore: new InMemoryKyaNonceStore(),
        clock,
      }),
      delegation: new ModernKyaDelegationVerifier({
        signatures: new OfficialEddsaJcs2022Verifier(resolver),
        revocation: input.revocation ?? (async () => ({ revoked: false, fresh: true })),
      }),
    }),
  });
}

describe("KYA authority gate", () => {
  it("issues a signed BLOCK when required KYA is missing", async () => {
    const fixture = await buildKyaFixture();
    const decision = await (await gate({ fixture })).evaluate({ action: fixture.action });
    expect(decision.verdict).toBe("BLOCK");
    expect(decision.reason_codes).toContain("KYA_AUTHORITY_REQUIRED");
    expect(decision.signing.signature).not.toBe("");
  });

  it("allows valid KYA only when normal Inntris policy also allows", async () => {
    const fixture = await buildKyaFixture();
    const decision = await (
      await gate({ fixture })
    ).evaluate({
      action: fixture.action,
      presentation: fixture.presentation,
    });
    expect(decision.verdict).toBe("ALLOW");

    const deniedFixture = await buildKyaFixture({ nonce: "AQIDBAUGBwgJCgsMDQ4PEQ" });
    const denied = await (
      await gate({ fixture: deniedFixture, policy: basePolicy({ transactionLimit: "20.00" }) })
    ).evaluate({ action: deniedFixture.action, presentation: deniedFixture.presentation });
    expect(denied.verdict).toBe("BLOCK");
    expect(denied.reason_codes).toContain("AMOUNT_EXCEEDS_TRANSACTION_LIMIT");
  });

  it("issues a signed BLOCK for invalid KYA and enforces the stricter KYA cap", async () => {
    const invalid = await buildKyaFixture({
      amount: "60.00",
      maxAmount: "50.00",
      nonce: "AQIDBAUGBwgJCgsMDQ4PFA",
    });
    const decision = await (
      await gate({ fixture: invalid, policy: basePolicy({ transactionLimit: "1000.00" }) })
    ).evaluate({ action: invalid.action, presentation: invalid.presentation });
    expect(decision).toMatchObject({
      verdict: "BLOCK",
      reason_codes: ["KYA_AMOUNT_EXCEEDS_DELEGATION"],
    });
    expect(decision.signing.signature).not.toBe("");
  });

  it("requires fresh KYA for approval and binds it to the superseding decision", async () => {
    const fixture = await buildKyaFixture({ amount: "80.00", nonce: "AQIDBAUGBwgJCgsMDQ4PEg" });
    const authorityGate = await gate({ fixture });
    const pending = await authorityGate.evaluate({
      action: fixture.action,
      presentation: fixture.presentation,
    });
    expect(pending.verdict).toBe("REQUIRE_APPROVAL");

    const fresh = await buildKyaFixture({ amount: "80.00", nonce: "AQIDBAUGBwgJCgsMDQ4PEw" });
    const resolved = await authorityGate.resolveApproval({
      approval: {
        decision_id: pending.decision_id,
        granted: true,
        approval_reference: "approval-1",
        approver_ids: ["reviewer-1"],
      },
      presentation: fresh.presentation,
    });
    expect(resolved.success).toBe(true);
    expect(resolved.decision?.verdict).toBe("ALLOW");
    expect(resolved.decision?.action_hash).not.toBe(pending.action_hash);
  });

  it("rejects approval when delegated authority is revoked after the initial decision", async () => {
    const fixture = await buildKyaFixture({ amount: "80.00", nonce: "AQIDBAUGBwgJCgsMDQ4PFQ" });
    let revoked = false;
    const authorityGate = await gate({
      fixture,
      revocation: async () => ({ revoked, fresh: true }),
    });
    const pending = await authorityGate.evaluate({
      action: fixture.action,
      presentation: fixture.presentation,
    });
    revoked = true;
    const fresh = await buildKyaFixture({ amount: "80.00", nonce: "AQIDBAUGBwgJCgsMDQ4PFg" });
    await expect(
      authorityGate.resolveApproval({
        approval: {
          decision_id: pending.decision_id,
          granted: true,
          approval_reference: "approval-revoked",
          approver_ids: ["reviewer-1"],
        },
        presentation: fresh.presentation,
      }),
    ).resolves.toMatchObject({
      success: false,
      reason_code: "KYA_DELEGATION_REVOKED",
    });
  });

  it("reuses a durable successful revalidation for the same execution retry", async () => {
    const fixture = await buildKyaFixture({ nonce: "AQIDBAUGBwgJCgsMDQ4PFA" });
    const authorityGate = await gate({ fixture });
    const decision = await authorityGate.evaluate({
      action: fixture.action,
      presentation: fixture.presentation,
    });
    const fresh = await buildKyaFixture({ nonce: "AQIDBAUGBwgJCgsMDQ4PFQ" });
    const consumption = {
      decision_id: decision.decision_id,
      action_hash: decision.action_hash,
      execution_ref: "x402-payment-1",
    };
    const first = await authorityGate.consume({ consumption, presentation: fresh.presentation });
    const retry = await authorityGate.consume({ consumption, presentation: fresh.presentation });
    expect(first.status).toBe("consumed");
    expect(retry.status).toBe("idempotent");

    const changed = await authorityGate.consume({
      consumption: { ...consumption, execution_ref: "x402-payment-2" },
      presentation: fresh.presentation,
    });
    expect(changed).toMatchObject({
      success: false,
      reason_code: "KYA_PROOF_REPLAYED",
    });

    const changedHash = await authorityGate.consume({
      consumption: { ...consumption, action_hash: `sha256:${"f".repeat(64)}` },
      presentation: fresh.presentation,
    });
    expect(changedHash).toMatchObject({
      success: false,
      reason_code: "ACTION_HASH_MISMATCH",
    });
  });

  it("fails closed when authority state cannot be persisted", async () => {
    const fixture = await buildKyaFixture({ nonce: "AQIDBAUGBwgJCgsMDQ4PFw" });
    const unavailable: KyaAuthorityStateStore = {
      durability: "durable",
      saveDecisionAuthority: async () => Promise.reject(new Error("store unavailable")),
      getDecisionAuthority: async () => Promise.reject(new Error("store unavailable")),
      appendRevalidation: async () => Promise.reject(new Error("store unavailable")),
      getSuccessfulExecutionRevalidation: async () =>
        Promise.reject(new Error("store unavailable")),
    };
    await expect(
      (await gate({ fixture, stateStore: unavailable })).evaluate({
        action: fixture.action,
        presentation: fixture.presentation,
      }),
    ).rejects.toMatchObject({ reasonCode: "KYA_AUTHORITY_STATE_UNAVAILABLE" });
  });

  it("records KYA verification, gate and replay metrics without proof data", async () => {
    const fixture = await buildKyaFixture({ nonce: "AQIDBAUGBwgJCgsMDQ4PGA" });
    const metrics = new InMemoryKyaMetrics();
    const authorityGate = await gate({ fixture, metrics });
    await authorityGate.evaluate({ action: fixture.action, presentation: fixture.presentation });
    expect(metrics.verifications.get("verified:complete")).toBe(1);
    expect(metrics.authorityGates.get("ALLOW")).toBe(1);
  });
});
