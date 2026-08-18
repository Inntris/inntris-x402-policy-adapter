import { hashAction } from "@inntris/decision-core";
import { verifyDecision, verifySignedDecision } from "@inntris/decision-verifier";
import {
  actionFromX402,
  paymentRequirementsHash,
  type X402SettlementInput,
} from "@inntris/x402-adapter";
import { afterAll, describe, expect, it } from "vitest";

import { honestInput, honestRequirements, paymentPayload, securityContext } from "./harness.js";
import { flushEvidence, recordEvidence } from "./evidence.js";

afterAll(async () => {
  await flushEvidence("d5-offline-detectability");
});

/**
 * What a verifier is assumed to hold. The product claim is that a receipt can
 * be checked "without an Inntris account, API, database or blockchain node",
 * so `receipt-only` is the claim's own standard: the signed decision plus the
 * public key registry, and nothing else.
 */
type VerifierKnowledge = "receipt-only" | "receipt-plus-served-requirements" | "requires-external";

interface DetectabilityCase {
  id: string;
  substitution: string;
  mutate: (input: X402SettlementInput) => X402SettlementInput;
  /** What a receipt-only verifier would need in order to notice. */
  needs: string;
  expected: VerifierKnowledge;
}

const CASES: DetectabilityCase[] = [
  {
    id: "payTo",
    substitution: "Recipient substituted in the quoted requirements",
    mutate: (input) => ({
      ...input,
      paymentRequirements: {
        ...input.paymentRequirements,
        payTo: "0x00000000000000000000000000000000000000ff",
      },
    }),
    needs: "the payee allowlist, which the receipt does not carry",
    expected: "receipt-plus-served-requirements",
  },
  {
    id: "amount-atomic",
    substitution: "Atomic amount substituted in the quoted requirements",
    mutate: (input) => ({
      ...input,
      paymentRequirements: { ...input.paymentRequirements, amount: "9000000" },
    }),
    needs: "the requirements actually served, to compare against payment_requirements_hash",
    expected: "receipt-plus-served-requirements",
  },
  {
    id: "assetDecimals",
    substitution: "F-1. Declared asset precision rescales the decimal amount",
    mutate: (input) => ({ ...input, assetDecimals: 9 }),
    needs:
      "independent knowledge of the asset's true precision, which appears nowhere in the receipt",
    expected: "requires-external",
  },
  {
    id: "inner-authorization",
    substitution: "F-4. Signed authorisation diverges from the accepted requirements",
    mutate: (input) => ({
      ...input,
      paymentPayload: paymentPayload({
        to: "0x00000000000000000000000000000000000000ff",
        value: "1",
      }),
    }),
    needs: "the payload itself, to recompute the payload hash and inspect the inner authorisation",
    expected: "requires-external",
  },
  {
    id: "scheme",
    substitution: "F-7. Scheme named in the receipt was never evaluated",
    mutate: (input) => ({
      ...input,
      paymentRequirements: { ...input.paymentRequirements, scheme: "deferred" },
    }),
    needs:
      "the requirements actually served — scheme is inside payment_requirements_hash, so a substitution is caught, though the receipt still cannot show the field was never evaluated",
    expected: "receipt-plus-served-requirements",
  },
  {
    id: "agentId",
    substitution: "F-7. Agent named in the receipt was never evaluated",
    mutate: (input) => ({ ...input, agentId: "agent_impostor" }),
    needs: "the policy source, to learn that evaluatePolicy never reads agent_id",
    expected: "requires-external",
  },
  {
    id: "maxTimeoutSeconds",
    substitution: "F-7. Requirement timeout bound into the hash but never compared to expiry",
    mutate: (input) => ({
      ...input,
      paymentRequirements: { ...input.paymentRequirements, maxTimeoutSeconds: 86_400 },
    }),
    needs:
      "the requirements actually served — the value is inside payment_requirements_hash even though it is not surfaced as a receipt field",
    expected: "receipt-plus-served-requirements",
  },
  {
    id: "validBefore",
    substitution: "F-7. Authorisation validity window never compared to decision expiry",
    mutate: (input) => ({ ...input, paymentPayload: paymentPayload({ validBefore: "1" }) }),
    needs: "the payload, to read validBefore and compare it to expires_at",
    expected: "requires-external",
  },
  {
    id: "principalId",
    substitution: "F-5. Principal chosen by the caller, keying the cumulative budget",
    mutate: (input) => ({ ...input, principalId: "org_attacker" }),
    needs: "the credential-to-tenancy mapping, which is not modelled anywhere",
    expected: "requires-external",
  },
];

describe("D5 offline detectability", () => {
  it.each(CASES)("classifies detectability of $id", async (testCase) => {
    const context = await securityContext();
    const honestAction = actionFromX402(honestInput);
    const mutatedInput = testCase.mutate(honestInput);
    const mutatedAction = actionFromX402(mutatedInput);
    const decision = await context.guard.authorise(mutatedInput);

    // 1. Receipt-only: signature and internal consistency, nothing else.
    const receiptOnly = verifySignedDecision(decision, context.keyRegistry);

    // 2. Receipt plus the requirements a verifier independently knows were
    //    served, which is the strongest position short of external lookup.
    const withServedRequirements = verifyDecision({
      decision,
      action: mutatedAction,
      keyRegistry: context.keyRegistry,
      at: context.clock.now(),
      expectedPaymentRequirementsHash: paymentRequirementsHash(honestRequirements),
    });

    const detectableReceiptOnly = !receiptOnly.valid;
    const detectableWithRequirements = !withServedRequirements.valid;
    const actual: VerifierKnowledge = detectableReceiptOnly
      ? "receipt-only"
      : detectableWithRequirements
        ? "receipt-plus-served-requirements"
        : "requires-external";

    expect(actual).toBe(testCase.expected);
    // Every mutation still yields a receipt that verifies as a signed envelope.
    expect(receiptOnly.valid).toBe(true);
    expect(hashAction(mutatedAction)).toBe(decision.action_hash);
    expect(hashAction(honestAction)).not.toBe(decision.action_hash);

    recordEvidence({
      id: `D5:${testCase.id}`,
      deliverable: "D5",
      attack: testCase.substitution,
      status: actual === "requires-external" ? "KNOWN_GAP" : "PASS",
      expectation:
        "A verifier holding only the receipt should be able to tell that a policy-bearing value was substituted.",
      observed: `receipt-only verification: ${receiptOnly.valid ? "valid, substitution NOT detectable" : "invalid, detectable"}. With the served requirements supplied: ${withServedRequirements.valid ? "still not detectable" : `detectable (${withServedRequirements.reason_codes.join(", ")})`}. To notice, a verifier needs ${testCase.needs}.`,
      enforcement: actual === "requires-external" ? "NONE" : "INNTRIS",
      reason_codes: withServedRequirements.reason_codes,
      settlement_invoked: false,
      resource_served: false,
    });
  });

  it("F-7: the receipt cannot show that a bound field was never evaluated", async () => {
    const context = await securityContext();

    // Every one of these is carried into the signed receipt, and none is read
    // by evaluatePolicy. Two of them are additionally inside the requirements
    // hash, so a *substitution* is detectable given the served requirements —
    // but that is a different question from whether the field was evaluated.
    const decision = await context.guard.authorise({
      ...honestInput,
      agentId: "agent_impostor",
      paymentRequirements: {
        ...honestRequirements,
        scheme: "deferred",
        maxTimeoutSeconds: 86_400,
      },
      paymentPayload: paymentPayload({
        accepted: { ...honestRequirements, scheme: "deferred", maxTimeoutSeconds: 86_400 },
        validBefore: "1",
      }),
    });

    expect(decision.verdict).toBe("ALLOW");
    expect(verifySignedDecision(decision, context.keyRegistry).valid).toBe(true);
    expect(decision.protocol_reference).toMatchObject({ scheme: "deferred" });
    expect(decision.agent_id).toBe("agent_impostor");
    // The reason codes are the only account the receipt gives of what was
    // checked, and they name no field.
    expect(decision.reason_codes).toEqual([
      "MERCHANT_ALLOWED",
      "WITHIN_TRANSACTION_LIMIT",
      "WITHIN_DAILY_LIMIT",
    ]);

    recordEvidence({
      id: "D5:F7-unevaluated-not-detectable",
      deliverable: "D5",
      attack: "F-7. Telling from the receipt alone which bound fields were actually evaluated",
      status: "KNOWN_GAP",
      expectation:
        "A receipt should let a verifier distinguish a field the issuer checked from one it merely copied.",
      observed:
        "A signed ALLOW carrying scheme=deferred, agent_id=agent_impostor, maxTimeoutSeconds=86400 and an authorisation whose validBefore is in the past verifies cleanly. Its reason codes — MERCHANT_ALLOWED, WITHIN_TRANSACTION_LIMIT, WITHIN_DAILY_LIMIT — name no field, so nothing in the receipt distinguishes an evaluated field from a copied one. Substitution of scheme or maxTimeoutSeconds is separately detectable to a verifier holding the served requirements, because both sit inside payment_requirements_hash; that detects a changed value, not an unchecked one.",
      enforcement: "NONE",
      reason_codes: decision.reason_codes,
      settlement_invoked: false,
      resource_served: false,
    });
  });

  it("F-6: a receipt does not record which integration path produced it", async () => {
    const context = await securityContext();

    // The library path derives the action from requirements it holds.
    const derived = await context.guard.authorise(honestInput);
    // The HTTP path signs an action the caller authored in full. Modelled here
    // by handing the provider the same action directly, which is exactly what
    // the endpoint does with the request body.
    const asserted = await context.provider.evaluate(actionFromX402(honestInput));

    const strippedDerived = {
      ...derived,
      decision_id: "",
      nonce: "",
      issued_at: "",
      expires_at: "",
      decision_fingerprint: "",
      signing: {},
    };
    const strippedAsserted = {
      ...asserted,
      decision_id: "",
      nonce: "",
      issued_at: "",
      expires_at: "",
      decision_fingerprint: "",
      signing: {},
    };

    expect(verifySignedDecision(derived, context.keyRegistry).valid).toBe(true);
    expect(verifySignedDecision(asserted, context.keyRegistry).valid).toBe(true);
    // Identical in every field that carries meaning.
    expect(strippedAsserted).toEqual(strippedDerived);

    recordEvidence({
      id: "D5:F6-path-indistinguishable",
      deliverable: "D5",
      attack: "F-6. Distinguishing a derived receipt from a caller-asserted one, offline",
      status: "KNOWN_GAP",
      expectation:
        "A verifier should be able to tell whether the issuer derived the facts it signed or accepted them from the caller.",
      observed:
        "A decision produced through InntrisX402Guard.authorise and one produced by handing provider.evaluate a caller-authored action are field-identical once the per-issuance values are removed, and both verify. inntris-decision-v1 carries no provenance or derivation-path field, so the distinction is not recoverable from the receipt.",
      enforcement: "NONE",
      reason_codes: [],
      settlement_invoked: false,
      resource_served: false,
      notes: "See docs/security/F6_RECEIPT_TRUST_OPTIONS.md.",
    });
  });
});
