import { type Clock, type InntrisActionV1, type KeyRegistry } from "@inntris/decision-core";
import { verifyDecision } from "@inntris/decision-verifier";
import type { KyaAuthorityPresentation, KyaGate } from "@inntris/kya-os-authority";

export interface KyaAuthorityConformanceOptions {
  gate: KyaGate;
  keyRegistry: KeyRegistry;
  clock: Clock;
  expectedPolicyVersion: string;
  valid: { action: InntrisActionV1; presentation: KyaAuthorityPresentation };
  mutatedRequest: { action: InntrisActionV1; presentation: KyaAuthorityPresentation };
  getBoundAction(decisionId: string): Promise<InntrisActionV1>;
  mutatePayment(action: InntrisActionV1): InntrisActionV1;
  overDelegation: { action: InntrisActionV1; presentation: KyaAuthorityPresentation };
  organisationalDeny: { action: InntrisActionV1; presentation: KyaAuthorityPresentation };
}

export interface KyaAuthorityConformanceReport {
  passed: true;
  validDecisionId: string;
  checks: readonly [
    "valid_authority",
    "request_mutation",
    "payment_mutation",
    "delegation_cap",
    "organisational_policy",
  ];
}

function assert(condition: boolean, message: string): asserts condition {
  if (!condition) throw new Error(`KYA conformance failed: ${message}`);
}

export async function runKyaAuthorityConformance(
  options: KyaAuthorityConformanceOptions,
): Promise<KyaAuthorityConformanceReport> {
  const valid = await options.gate.evaluate(options.valid);
  assert(valid.verdict === "ALLOW", "valid delegated authority did not reach Inntris ALLOW");

  const requestMutation = await options.gate.evaluate(options.mutatedRequest);
  assert(
    requestMutation.verdict === "BLOCK" &&
      requestMutation.reason_codes.some((code) =>
        ["KYA_PROOF_INVALID", "KYA_PROOF_REPLAYED"].includes(code),
      ),
    "exact request mutation did not invalidate KYA proof",
  );

  const boundAction = await options.getBoundAction(valid.decision_id);
  const baselineVerification = verifyDecision({
    decision: valid,
    action: boundAction,
    keyRegistry: options.keyRegistry,
    at: options.clock.now(),
    expectedPolicyVersion: options.expectedPolicyVersion,
  });
  assert(baselineVerification.valid, "valid bound Decision Envelope did not verify");
  const paymentMutation = verifyDecision({
    decision: valid,
    action: options.mutatePayment(boundAction),
    keyRegistry: options.keyRegistry,
    at: options.clock.now(),
    expectedPolicyVersion: options.expectedPolicyVersion,
  });
  assert(
    !paymentMutation.valid && paymentMutation.reason_codes.includes("ACTION_HASH_MISMATCH"),
    "exact payment mutation did not invalidate the Decision Envelope",
  );

  const overDelegation = await options.gate.evaluate(options.overDelegation);
  assert(
    overDelegation.verdict === "BLOCK" &&
      overDelegation.reason_codes.includes("KYA_AMOUNT_EXCEEDS_DELEGATION"),
    "KYA MaxAmount did not block",
  );

  const organisationalDeny = await options.gate.evaluate(options.organisationalDeny);
  assert(
    organisationalDeny.verdict === "BLOCK" &&
      !organisationalDeny.reason_codes.some((code) => code.startsWith("KYA_")),
    "verified KYA authority bypassed Inntris organisational policy",
  );

  return {
    passed: true,
    validDecisionId: valid.decision_id,
    checks: [
      "valid_authority",
      "request_mutation",
      "payment_mutation",
      "delegation_cap",
      "organisational_policy",
    ],
  };
}
