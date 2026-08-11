import {
  buildKeyRegistryEntry,
  createPublicDemoSigner,
  type KeyRegistry,
} from "@inntris/decision-core";
import {
  DefaultKyaAuthorityVerifier,
  InMemoryKyaAuthorityStateStore,
  InMemoryKyaNonceStore,
  KyaAuthorityGate,
  ModernKyaDelegationVerifier,
  OfficialEddsaJcs2022Verifier,
  ProductionKyaDidResolver,
  UpstreamKyaRequestProofVerifier,
  KyaPaymentRequestV1Schema,
} from "@inntris/kya-os-authority";
import { runKyaAuthorityConformance } from "@inntris/multi-rail-conformance";
import { LocalPolicyDecisionProvider, type InntrisPolicyV1 } from "@inntris/policy-engine";
import { describe, expect, it } from "vitest";

import { MutableClock } from "../helpers.js";
import { buildKyaFixture, INNTRIS_RESOURCE, KYA_NOW, PAYEE } from "../kya-helpers.js";

function policy(): InntrisPolicyV1 {
  return {
    version: 1,
    policy_id: "kya-conformance-policy",
    policy_version: "1",
    defaults: { verdict: "BLOCK", decision_ttl_seconds: 60 },
    rails: { x402: { allowed_networks: ["eip155:8453"], allowed_assets: ["USDC"] } },
    limits: { per_transaction: "100.00", daily: "500.00" },
    approval: { require_human_above: "100.00" },
    merchants: [
      {
        merchant_id: "kya-merchant",
        payees: [PAYEE],
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

describe("KYA authority conformance", () => {
  it("proves authority, mutation, delegation cap and organisational policy invariants", async () => {
    const valid = await buildKyaFixture({ nonce: "AQIDBAUGBwgJCgsMDQ4PIA" });
    const mutatedRequest = await buildKyaFixture({ nonce: "AQIDBAUGBwgJCgsMDQ4PIQ" });
    const request = KyaPaymentRequestV1Schema.parse(
      structuredClone(mutatedRequest.presentation.request),
    );
    request.params.arguments.amount = "43.00";
    const overDelegation = await buildKyaFixture({
      nonce: "AQIDBAUGBwgJCgsMDQ4PIg",
      amount: "501.00",
      maxAmount: "500.00",
    });
    const organisationalDeny = await buildKyaFixture({
      nonce: "AQIDBAUGBwgJCgsMDQ4PIw",
      amount: "120.00",
      maxAmount: "500.00",
    });
    const clock = new MutableClock(KYA_NOW);
    const signer = createPublicDemoSigner();
    const keyRegistry: KeyRegistry = {
      version: "inntris-key-registry-v1",
      keys: [buildKeyRegistryEntry(signer, { notBefore: new Date("2026-01-01T00:00:00.000Z") })],
    };
    const provider = new LocalPolicyDecisionProvider({ policy: policy(), signer, clock });
    const resolver = new ProductionKyaDidResolver();
    const stateStore = new InMemoryKyaAuthorityStateStore();
    const gate = new KyaAuthorityGate({
      provider,
      authorityPolicy: valid.policy,
      stateStore,
      clock,
      verifier: new DefaultKyaAuthorityVerifier({
        requestProof: new UpstreamKyaRequestProofVerifier({
          resolver,
          nonceStore: new InMemoryKyaNonceStore(),
          clock,
        }),
        delegation: new ModernKyaDelegationVerifier({
          signatures: new OfficialEddsaJcs2022Verifier(resolver),
          revocation: async () => ({ revoked: false, fresh: true }),
        }),
      }),
    });
    const report = await runKyaAuthorityConformance({
      gate,
      keyRegistry,
      clock,
      expectedPolicyVersion: "1",
      valid: { action: valid.action, presentation: valid.presentation },
      mutatedRequest: {
        action: mutatedRequest.action,
        presentation: { ...mutatedRequest.presentation, request },
      },
      getBoundAction: async (decisionId) => {
        const record = await stateStore.getDecisionAuthority(decisionId);
        if (record === undefined) throw new Error("missing KYA conformance authority record");
        return record.action;
      },
      mutatePayment: (action) => ({
        ...action,
        transaction: { ...action.transaction, amount: "43.00" },
      }),
      overDelegation: {
        action: overDelegation.action,
        presentation: overDelegation.presentation,
      },
      organisationalDeny: {
        action: organisationalDeny.action,
        presentation: organisationalDeny.presentation,
      },
    });
    expect(report).toMatchObject({ passed: true });
    expect(report.checks).toHaveLength(5);
  });
});
