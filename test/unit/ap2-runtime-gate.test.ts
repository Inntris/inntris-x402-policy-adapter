import {
  AP2_OFFICIAL_REPOSITORY,
  AP2_OFFICIAL_SDK_COMMIT,
  AP2_PROTOCOL_VERSION,
  InMemoryAP2ExecutionStore,
  InntrisAP2RuntimeGate,
  verifyAP2ActionReceipt,
  type AP2ExecutionStore,
  type AP2OfficialVerification,
  type AP2RuntimeGateInput,
  type AP2TrustProvider,
} from "@inntris/ap2-runtime-gate";
import { createPublicDemoSigner } from "@inntris/decision-core";
import { describe, expect, it, vi } from "vitest";

import { testContext } from "../helpers.js";

const hash = (character: string): `sha256:${string}` => `sha256:${character.repeat(64)}`;

const baseInput: AP2RuntimeGateInput = {
  mandates: {
    version: "inntris-ap2-mandate-presentation-v1",
    checkout_mandate_token: "checkout.open~~checkout.closed",
    payment_mandate_token: "payment.open~~payment.closed",
    checkout_jwt: "merchant.checkout.jwt",
    checkout_audience: "merchant-research-api",
    checkout_nonce: "checkout-nonce",
    checkout_issuer: "merchant-research-api",
    payment_audience: "payment-processor",
    payment_nonce: "payment-nonce",
  },
  principalId: "org_demo",
  agentId: "agent_research_01",
  resource: "https://example.test/research",
  purpose: "research_api",
  expectedMerchantId: "merchant-research-api",
  expectedAmountMinor: "4500",
  expectedCurrency: "USD",
};

function verification(
  overrides: {
    intent?: Partial<AP2OfficialVerification["intent"]>;
    checkout?: Partial<AP2OfficialVerification["checkout"]>;
    payment?: Partial<AP2OfficialVerification["payment"]>;
    verified_at?: string;
  } = {},
): AP2OfficialVerification {
  return {
    version: "inntris-ap2-official-verification-v1",
    sdk: {
      repository: AP2_OFFICIAL_REPOSITORY,
      commit: AP2_OFFICIAL_SDK_COMMIT,
      protocol_version: AP2_PROTOCOL_VERSION,
    },
    mode: "autonomous",
    intent: {
      verified: true,
      checkout_open_mandate_hash: hash("1"),
      payment_open_mandate_hash: hash("2"),
      ...overrides.intent,
    },
    checkout: {
      verified: true,
      mandate_hash: hash("3"),
      expires_at: "2026-07-29T12:05:00.000Z",
      checkout_hash: "checkoutHashA",
      checkout_id: "checkout-A",
      merchant_id: "merchant-research-api",
      merchant_name: "Research API",
      ...overrides.checkout,
    },
    payment: {
      verified: true,
      mandate_hash: hash("4"),
      expires_at: "2026-07-29T12:05:00.000Z",
      transaction_id: "checkoutHashA",
      payee_id: "merchant-research-api",
      payee_name: "Research API",
      amount_minor: "4500",
      currency: "USD",
      payment_instrument_type: "card",
      ...overrides.payment,
    },
    verified_at: overrides.verified_at ?? "2026-07-29T12:00:00.000Z",
  };
}

const trustProvider: AP2TrustProvider = {
  resolve: async () => ({
    issuerPublicJwk: { kty: "EC", kid: "user-key" },
    merchantPublicJwk: { kty: "EC", kid: "merchant-key" },
  }),
};

async function gateContext(
  evidence: unknown = verification(),
  executionStore: AP2ExecutionStore = new InMemoryAP2ExecutionStore(),
  trust: AP2TrustProvider = trustProvider,
  currencyDecimals: Readonly<Record<string, number>> = { USD: 2 },
) {
  const context = await testContext();
  const verify = vi.fn(async () => evidence);
  const gate = new InntrisAP2RuntimeGate({
    provider: context.provider,
    keyRegistry: context.keyRegistry,
    verifier: { verify },
    trustProvider: trust,
    receiptSigner: createPublicDemoSigner(),
    executionStore,
    expectedPolicyVersion: "1",
    currencyDecimals,
    clock: context.clock,
  });
  return { ...context, gate, verify };
}

function gateReason(reasonCode: string): { name: string; reasonCode: string } {
  return {
    name: "InntrisAP2RuntimeGateError",
    reasonCode,
  };
}

describe("AP2 runtime gate", () => {
  it("executes once and returns the signed receipt on an exact retry", async () => {
    const context = await gateContext();
    const delegate = vi.fn(async () => ({ settlement: "authorised" }));

    const first = await context.gate.process(baseInput, delegate);
    const replay = await context.gate.process(baseInput, delegate);

    expect(first.replayed).toBe(false);
    expect(replay.replayed).toBe(true);
    expect(replay.receipt).toEqual(first.receipt);
    expect(replay.result).toEqual(first.result);
    expect(delegate).toHaveBeenCalledTimes(1);
    expect(first.action.rail).toBe("ap2");
    expect(first.action.protocol_reference.type).toBe("ap2");
    expect(verifyAP2ActionReceipt(first.receipt, context.keyRegistry)).toMatchObject({
      valid: true,
    });
  });

  it("blocks a valid AP2 mandate when current organisational policy denies it", async () => {
    const context = await gateContext(verification({ payment: { amount_minor: "15000" } }));
    const delegate = vi.fn(async () => ({ ok: true }));

    await expect(
      context.gate.process(
        {
          ...baseInput,
          expectedAmountMinor: "15000",
        },
        delegate,
      ),
    ).rejects.toMatchObject(gateReason("DECISION_NOT_ALLOW"));
    expect(delegate).not.toHaveBeenCalled();
  });

  it("uses the verified payment instrument as the policy network", async () => {
    const context = await gateContext(
      verification({ payment: { payment_instrument_type: "bank_account" } }),
    );
    const delegate = vi.fn(async () => ({ ok: true }));

    await expect(context.gate.process(baseInput, delegate)).rejects.toMatchObject(
      gateReason("DECISION_NOT_ALLOW"),
    );
    expect(delegate).not.toHaveBeenCalled();
  });

  it("requires an operator configured currency minor unit mapping", async () => {
    const context = await gateContext(verification(), undefined, trustProvider, {});
    const delegate = vi.fn(async () => ({ ok: true }));

    await expect(context.gate.process(baseInput, delegate)).rejects.toMatchObject(
      gateReason("INVALID_AP2_INPUT"),
    );
    expect(delegate).not.toHaveBeenCalled();
  });

  it("fails closed when official AP2 verification rejects the mandate", async () => {
    const context = await gateContext();
    context.verify.mockRejectedValueOnce(new Error("invalid signature"));
    const delegate = vi.fn(async () => ({ ok: true }));

    await expect(context.gate.process(baseInput, delegate)).rejects.toMatchObject(
      gateReason("AP2_VERIFICATION_FAILED"),
    );
    expect(delegate).not.toHaveBeenCalled();
  });

  it("rejects stale, future, and expired AP2 evidence", async () => {
    const stale = await gateContext(verification({ verified_at: "2026-07-29T11:59:29.000Z" }));
    await expect(stale.gate.process(baseInput, async () => ({ ok: true }))).rejects.toMatchObject(
      gateReason("AP2_VERIFICATION_STALE"),
    );

    const future = await gateContext(verification({ verified_at: "2026-07-29T12:00:01.000Z" }));
    await expect(future.gate.process(baseInput, async () => ({ ok: true }))).rejects.toMatchObject(
      gateReason("AP2_VERIFICATION_STALE"),
    );

    const expired = await gateContext(
      verification({ checkout: { expires_at: "2026-07-29T12:00:00.000Z" } }),
    );
    await expect(expired.gate.process(baseInput, async () => ({ ok: true }))).rejects.toMatchObject(
      gateReason("AP2_MANDATE_EXPIRED"),
    );
  });

  it("rejects merchant, amount, currency, checkout, and intent substitution", async () => {
    const cases: [AP2OfficialVerification, string][] = [
      [verification({ checkout: { merchant_id: "attacker" } }), "AP2_CHECKOUT_BINDING_MISMATCH"],
      [verification({ payment: { amount_minor: "4501" } }), "AP2_PAYMENT_BINDING_MISMATCH"],
      [verification({ payment: { currency: "EUR" } }), "AP2_PAYMENT_BINDING_MISMATCH"],
      [
        verification({ payment: { transaction_id: "differentCheckoutHash" } }),
        "AP2_PAYMENT_BINDING_MISMATCH",
      ],
      [verification({ intent: { verified: false } }), "AP2_INTENT_INVALID"],
    ];

    for (const [evidence, reasonCode] of cases) {
      const context = await gateContext(evidence);
      await expect(
        context.gate.process(baseInput, async () => ({ ok: true })),
      ).rejects.toMatchObject(gateReason(reasonCode));
    }
  });

  it("rejects a Payment Mandate replay bound to a different action", async () => {
    const store = new InMemoryAP2ExecutionStore();
    const first = await gateContext(verification(), store);
    await first.gate.process(baseInput, async () => ({ ok: true }));

    const second = await gateContext(verification(), store);
    await expect(
      second.gate.process(
        {
          ...baseInput,
          extensions: { request_id: "different-action" },
        },
        async () => ({ ok: true }),
      ),
    ).rejects.toMatchObject(gateReason("AP2_EXECUTION_CONFLICT"));
  });

  it("leaves a failed delegate claimed for reconciliation", async () => {
    const context = await gateContext();
    await expect(
      context.gate.process(baseInput, async () => {
        throw new Error("processor timeout");
      }),
    ).rejects.toMatchObject(gateReason("AP2_DELEGATE_FAILED"));

    await expect(context.gate.process(baseInput, async () => ({ ok: true }))).rejects.toMatchObject(
      gateReason("AP2_EXECUTION_IN_PROGRESS"),
    );
  });

  it("fails closed when trust, consumption, or execution state is unavailable", async () => {
    const unavailableTrust: AP2TrustProvider = {
      resolve: async () => {
        throw new Error("trust registry offline");
      },
    };
    const trustContext = await gateContext(verification(), undefined, unavailableTrust);
    await expect(
      trustContext.gate.process(baseInput, async () => ({ ok: true })),
    ).rejects.toMatchObject(gateReason("AP2_TRUST_UNAVAILABLE"));

    const consumptionContext = await gateContext();
    vi.spyOn(consumptionContext.provider, "consume").mockRejectedValueOnce(
      new Error("nonce store offline"),
    );
    await expect(
      consumptionContext.gate.process(baseInput, async () => ({ ok: true })),
    ).rejects.toMatchObject(gateReason("DECISION_CONSUMPTION_FAILED"));

    const unavailableStore: AP2ExecutionStore = {
      claim: async () => {
        throw new Error("store offline");
      },
      complete: async () => {
        throw new Error("store offline");
      },
    };
    const storeContext = await gateContext(verification(), unavailableStore);
    await expect(
      storeContext.gate.process(baseInput, async () => ({ ok: true })),
    ).rejects.toMatchObject(gateReason("AP2_EXECUTION_STORE_UNAVAILABLE"));
  });

  it("requires evidence from the pinned official AP2 SDK", async () => {
    const mismatched = structuredClone(verification()) as Record<string, unknown>;
    mismatched.sdk = {
      repository: AP2_OFFICIAL_REPOSITORY,
      commit: "untrusted-commit",
      protocol_version: AP2_PROTOCOL_VERSION,
    };
    const context = await gateContext(mismatched);

    await expect(context.gate.process(baseInput, async () => ({ ok: true }))).rejects.toMatchObject(
      gateReason("AP2_SDK_PROVENANCE_MISMATCH"),
    );
  });

  it("detects receipt tampering", async () => {
    const context = await gateContext();
    const result = await context.gate.process(baseInput, async () => ({ ok: true }));
    const tampered = {
      ...result.receipt,
      transaction_id: "tamperedTransaction",
    };

    expect(verifyAP2ActionReceipt(tampered, context.keyRegistry).valid).toBe(false);
  });
});
