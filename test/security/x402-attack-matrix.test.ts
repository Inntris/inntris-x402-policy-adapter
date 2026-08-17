import { resolve } from "node:path";

import { InntrisGuardError, X402BindingError } from "@inntris/x402-adapter";
import { afterAll, describe, expect, it, vi } from "vitest";

import {
  FakeFacilitator,
  GuardedResourceServer,
  honestInput,
  honestRequirements,
  paymentPayload,
  recordEvidence,
  securityContext,
  withRequirements,
  writeEvidence,
} from "./harness.js";

const ATTACKER_PAYEE = "0x00000000000000000000000000000000000000ff";

afterAll(async () => {
  await writeEvidence(resolve("evidence/x402-security-review.json"));
});

/**
 * Runs a substitution attack twice: once as a direct request for the
 * substituted value, which organisational policy must refuse outright, and
 * once as a swap performed after a legitimate authorisation, which the
 * settlement binding must refuse.
 */
async function substitutionAttack(input: {
  id: string;
  attack: string;
  substituted: Record<string, string>;
  expectedPolicyReason: string;
}): Promise<void> {
  const direct = await securityContext();
  const directDecision = await direct.guard.authorise(withRequirements(input.substituted));
  expect(directDecision.verdict).toBe("BLOCK");
  expect(directDecision.reason_codes).toContain(input.expectedPolicyReason);

  const swap = await securityContext();
  const authorised = await swap.guard.authorise(honestInput);
  expect(authorised.verdict).toBe("ALLOW");

  const settle = vi.fn(async () => "settled");
  const swapped = withRequirements(input.substituted);
  const error = await swap.guard
    .settleIfAuthorised(swapped, authorised, `execution-${input.id}`, settle)
    .then(() => null)
    .catch((thrown: unknown) => thrown);

  expect(error).toBeInstanceOf(InntrisGuardError);
  const guardError = error as InntrisGuardError;
  expect(settle).not.toHaveBeenCalled();

  recordEvidence({
    id: input.id,
    attack: input.attack,
    status: "PASS",
    expectation:
      "Policy blocks the substituted value outright, and a value swapped after authorisation is refused before settlement.",
    observed: `direct request: BLOCK (${directDecision.reason_codes.join(", ")}); post-authorisation swap: InntrisGuardError (${guardError.reasonCodes.join(", ")})`,
    reason_codes: [...directDecision.reason_codes, ...guardError.reasonCodes],
    settlement_invoked: settle.mock.calls.length > 0,
    resource_served: false,
  });
}

describe("A1 recipient substitution", () => {
  it("refuses an unlisted payee and any payee swapped after authorisation", async () => {
    await substitutionAttack({
      id: "A1",
      attack: "Recipient substitution (payTo redirected to an attacker address)",
      substituted: { payTo: ATTACKER_PAYEE },
      expectedPolicyReason: "PAYEE_NOT_ALLOWED",
    });
  });
});

describe("A2 asset substitution", () => {
  it("refuses an unlisted asset and any asset swapped after authorisation", async () => {
    await substitutionAttack({
      id: "A2",
      attack: "Asset substitution (settlement asset changed to an unlisted token)",
      substituted: { asset: "DAI" },
      expectedPolicyReason: "ASSET_NOT_ALLOWED",
    });
  });
});

describe("A3 amount substitution", () => {
  it("refuses an over-limit amount and any amount swapped after authorisation", async () => {
    await substitutionAttack({
      id: "A3",
      attack: "Amount substitution (settlement amount raised above the quoted price)",
      substituted: { amount: "150000000" },
      expectedPolicyReason: "AMOUNT_EXCEEDS_TRANSACTION_LIMIT",
    });
  });

  it("FINDING F-1: a caller-declared assetDecimals value rescales the amount policy sees", async () => {
    const context = await securityContext();
    const facilitator = new FakeFacilitator();
    const server = new GuardedResourceServer(context, facilitator);

    // 150000000 atomic units of 6-decimal USDC is 150.00, above the 100.00
    // per-transaction limit. Policy blocks it when the decimals are honest.
    const honestDecimals = withRequirements({ amount: "150000000" });
    const blocked = await context.guard.authorise(honestDecimals);
    expect(blocked.verdict).toBe("BLOCK");
    expect(blocked.reason_codes).toContain("AMOUNT_EXCEEDS_TRANSACTION_LIMIT");

    // The same on-chain transfer, declared as a 9-decimal asset, is presented
    // to policy as 0.15 and clears every limit. The action, the decision and
    // the payment-requirements hash all agree with each other, so downstream
    // verification cannot detect the rescaling.
    const understated = { ...honestDecimals, assetDecimals: 9 };
    const allowed = await context.guard.authorise(understated);
    expect(allowed.verdict).toBe("ALLOW");
    expect(allowed.transaction.amount).toBe("0.15");

    const outcome = await server.access({
      authorisationInput: understated,
      payload: paymentPayload({
        accepted: { ...honestRequirements, amount: "150000000" },
      }),
      executionRef: "execution-F1",
      decision: allowed,
    });

    expect(outcome.status).toBe(200);
    expect(facilitator.settleCalls).toHaveLength(1);

    recordEvidence({
      id: "A3-F1",
      attack:
        "Amount substitution via declared asset precision (assetDecimals supplied by the caller)",
      status: "FAIL",
      expectation:
        "The decimal amount policy evaluates should be derived from the asset, so an atomic amount cannot be rescaled below a limit.",
      observed:
        "assetDecimals is a caller-supplied parameter. Atomic amount 150000000 is BLOCKed as 150.00 at assetDecimals=6 and ALLOWed as 0.15 at assetDecimals=9. The signed decision, action hash and payment-requirements hash are mutually consistent in both cases, so verification does not detect the rescaling and settlement proceeds.",
      reason_codes: [...blocked.reason_codes, ...allowed.reason_codes],
      settlement_invoked: true,
      resource_served: true,
    });
  });
});

describe("A4 network substitution", () => {
  it("refuses an unlisted network and any network swapped after authorisation", async () => {
    await substitutionAttack({
      id: "A4",
      attack: "Network substitution (settlement moved to a different chain)",
      substituted: { network: "eip155:84532" },
      expectedPolicyReason: "NETWORK_NOT_ALLOWED",
    });
  });
});

describe("A5 expired authorisation", () => {
  it("refuses to settle or consume a decision after its TTL", async () => {
    const context = await securityContext();
    const facilitator = new FakeFacilitator();
    const server = new GuardedResourceServer(context, facilitator);
    const decision = await context.guard.authorise(honestInput);
    expect(decision.verdict).toBe("ALLOW");

    // The demo policy issues a 60 second decision TTL.
    context.clock.advance(61_000);

    const outcome = await server.access({
      authorisationInput: honestInput,
      payload: paymentPayload({}),
      executionRef: "execution-A5",
      decision,
    });
    const consumption = await context.guard.consumeBeforeExecution(decision, "execution-A5-direct");

    expect(outcome).toMatchObject({ status: 402, reasonCodes: ["DECISION_EXPIRED"] });
    expect(consumption).toMatchObject({ success: false, reason_code: "DECISION_EXPIRED" });
    expect(facilitator.settleCalls).toHaveLength(0);
    expect(server.served).toBe(0);

    recordEvidence({
      id: "A5",
      attack: "Expired authorisation (decision presented after its expiry)",
      status: "PASS",
      expectation:
        "An expired decision must not settle and must not be consumable, independently of the executor.",
      observed:
        "Settlement refused with DECISION_EXPIRED at the guard, and direct consumption independently refused with DECISION_EXPIRED at the provider. The facilitator was never called and the resource was not served.",
      reason_codes: ["DECISION_EXPIRED"],
      settlement_invoked: false,
      resource_served: false,
    });
  });
});

describe("A6 nonce and replay", () => {
  it("consumes a decision once and rejects a second execution reference as replay", async () => {
    const context = await securityContext();
    const decision = await context.guard.authorise(honestInput);
    const first = await context.guard.consumeBeforeExecution(decision, "execution-A6");
    const idempotent = await context.guard.consumeBeforeExecution(decision, "execution-A6");
    const replay = await context.guard.consumeBeforeExecution(decision, "execution-A6-replay");

    expect(first).toMatchObject({ success: true, status: "consumed" });
    expect(idempotent).toMatchObject({ success: true, status: "idempotent" });
    expect(idempotent.consumed_at).toBe(first.consumed_at);
    expect(replay).toMatchObject({
      success: false,
      status: "conflict",
      reason_code: "NONCE_ALREADY_CONSUMED",
    });

    recordEvidence({
      id: "A6",
      attack: "Nonce replay (one decision presented for a second, different execution)",
      status: "PASS",
      expectation:
        "A decision nonce must be consumable once. A retry of the same execution is idempotent; a different execution is a conflict.",
      observed:
        "First consumption: consumed. Same execution reference: idempotent, with the original consumed_at preserved. Different execution reference: conflict with NONCE_ALREADY_CONSUMED.",
      reason_codes: ["NONCE_ALREADY_CONSUMED"],
      settlement_invoked: false,
      resource_served: false,
    });
  });

  it("blocks a replayed settlement outright when a reconciliation store is configured", async () => {
    const context = await securityContext({ reconciliation: true });
    const facilitator = new FakeFacilitator();
    const server = new GuardedResourceServer(context, facilitator);
    const decision = await context.guard.authorise(honestInput);

    const first = await server.access({
      authorisationInput: honestInput,
      payload: paymentPayload({}),
      executionRef: "execution-A6-recon",
      decision,
    });
    const replaySameRef = await server.access({
      authorisationInput: honestInput,
      payload: paymentPayload({}),
      executionRef: "execution-A6-recon",
      decision,
    });
    const replayNewRef = await server.access({
      authorisationInput: honestInput,
      payload: paymentPayload({}),
      executionRef: "execution-A6-recon-2",
      decision,
    });

    expect(first.status).toBe(200);
    expect(replaySameRef).toMatchObject({
      status: 402,
      reasonCodes: ["EXECUTION_ALREADY_COMPLETED"],
    });
    expect(replayNewRef).toMatchObject({
      status: 402,
      reasonCodes: ["NONCE_ALREADY_CONSUMED"],
    });
    expect(facilitator.settleCalls).toHaveLength(1);
    expect(server.served).toBe(1);

    recordEvidence({
      id: "A6-recon",
      attack: "Settlement replay against a guard with execution reconciliation configured",
      status: "PASS",
      expectation:
        "A completed settlement must not be re-executed, whether the attacker reuses the execution reference or invents a new one.",
      observed:
        "Reused execution reference refused with EXECUTION_ALREADY_COMPLETED; new execution reference refused with NONCE_ALREADY_CONSUMED. The facilitator settled exactly once and the resource was served once.",
      reason_codes: ["EXECUTION_ALREADY_COMPLETED", "NONCE_ALREADY_CONSUMED"],
      settlement_invoked: true,
      resource_served: true,
    });
  });

  it("FINDING F-2: without a reconciliation store an identical retry settles a second time", async () => {
    const context = await securityContext();
    const facilitator = new FakeFacilitator();
    const server = new GuardedResourceServer(context, facilitator);
    const decision = await context.guard.authorise(honestInput);

    const first = await server.access({
      authorisationInput: honestInput,
      payload: paymentPayload({}),
      executionRef: "execution-F2",
      decision,
    });
    const retry = await server.access({
      authorisationInput: honestInput,
      payload: paymentPayload({}),
      executionRef: "execution-F2",
      decision,
    });

    expect(first.status).toBe(200);
    // The nonce store answers "idempotent" for an identical execution
    // reference, which the guard treats as a successful consumption. With no
    // reconciliation store there is nothing left to stop the executor.
    expect(retry.status).toBe(200);
    expect(facilitator.settleCalls).toHaveLength(2);
    expect(server.served).toBe(2);

    recordEvidence({
      id: "A6-F2",
      attack:
        "Settlement replay against a guard with no execution reconciliation store (the default)",
      status: "FAIL",
      expectation:
        "Replaying a settled payment should never invoke the settlement executor a second time.",
      observed:
        "InntrisX402Guard.settleIfAuthorised treats an idempotent nonce consumption as success and, with reconciliationStore left undefined, calls the settlement executor again. The facilitator settled twice and the resource was served twice for one authorisation.",
      reason_codes: [],
      settlement_invoked: true,
      resource_served: true,
    });
  });
});

describe("A7 insufficient balance", () => {
  it("does not settle or serve when the facilitator reports insufficient funds", async () => {
    const context = await securityContext({ reconciliation: true });
    const facilitator = new FakeFacilitator({
      verify: () => ({ isValid: false, invalidReason: "insufficient_funds" }),
    });
    const server = new GuardedResourceServer(context, facilitator);

    const outcome = await server.access({
      authorisationInput: honestInput,
      payload: paymentPayload({}),
      executionRef: "execution-A7",
    });

    expect(outcome).toMatchObject({ status: 402, reason: "insufficient_funds" });
    expect(facilitator.settleCalls).toHaveLength(0);
    expect(server.served).toBe(0);

    recordEvidence({
      id: "A7",
      attack: "Insufficient balance reported by the facilitator at verification time",
      status: "PASS",
      expectation:
        "A payer without funds must not have the resource released and must not reach settlement.",
      observed:
        "The integration refused at verification with insufficient_funds. Settlement was never invoked and the resource was not served. Note that balance is the facilitator's judgement, not the adapter's; see finding F-3 on ordering.",
      reason_codes: [],
      settlement_invoked: false,
      resource_served: false,
    });
  });

  it("records an unresolved operation when insufficient funds surface during settlement", async () => {
    const context = await securityContext({ reconciliation: true });
    const facilitator = new FakeFacilitator({
      settle: () => ({ success: false, errorReason: "insufficient_funds" }),
    });
    const server = new GuardedResourceServer(context, facilitator);

    const outcome = await server.access({
      authorisationInput: honestInput,
      payload: paymentPayload({}),
      executionRef: "execution-A7-late",
    });
    const unresolved = await context.reconciliationStore!.listUnresolved();

    expect(outcome).toMatchObject({
      status: 402,
      reasonCodes: ["EXECUTION_OUTCOME_UNKNOWN"],
    });
    expect(server.served).toBe(0);
    expect(unresolved).toHaveLength(1);
    expect(unresolved[0]).toMatchObject({
      status: "outcome_unknown",
      executionRef: "execution-A7-late",
    });

    recordEvidence({
      id: "A7-late",
      attack: "Insufficient balance surfacing only when settlement is attempted",
      status: "PASS",
      expectation:
        "A settlement that fails after it was attempted must not release the resource and must leave an operator-visible unresolved record.",
      observed:
        "Settlement raised EXECUTION_OUTCOME_UNKNOWN, the resource was not served, and one operation is listed as unresolved with status outcome_unknown pending authoritative resolution.",
      reason_codes: ["EXECUTION_OUTCOME_UNKNOWN"],
      settlement_invoked: true,
      resource_served: false,
    });
  });
});

describe("A8 facilitator verify=true followed by settlement failure", () => {
  it("blocks the resource, records the unknown outcome and refuses an automatic retry", async () => {
    const context = await securityContext({ reconciliation: true });
    const facilitator = new FakeFacilitator({
      settle: () => ({ success: false, errorReason: "settlement_timeout" }),
    });
    const server = new GuardedResourceServer(context, facilitator);
    const decision = await context.guard.authorise(honestInput);

    const outcome = await server.access({
      authorisationInput: honestInput,
      payload: paymentPayload({}),
      executionRef: "execution-A8",
      decision,
    });
    const retry = await server.access({
      authorisationInput: honestInput,
      payload: paymentPayload({}),
      executionRef: "execution-A8",
      decision,
    });
    const unresolved = await context.reconciliationStore!.listUnresolved();

    expect(facilitator.verifyCalls.length).toBeGreaterThan(0);
    expect(outcome).toMatchObject({ status: 402, reasonCodes: ["EXECUTION_OUTCOME_UNKNOWN"] });
    expect(retry).toMatchObject({ status: 402, reasonCodes: ["EXECUTION_OUTCOME_UNKNOWN"] });
    expect(facilitator.settleCalls).toHaveLength(1);
    expect(server.served).toBe(0);
    expect(unresolved[0]).toMatchObject({
      status: "outcome_unknown",
      lastErrorCode: "SettlementFailure",
    });

    recordEvidence({
      id: "A8",
      attack: "Facilitator verifies the payment as valid, then settlement fails or times out",
      status: "PASS",
      expectation:
        "An unknown settlement outcome must fail closed: no resource release, no automatic retry, and a durable record for reconciliation.",
      observed:
        "The first attempt raised EXECUTION_OUTCOME_UNKNOWN after one settlement call. The automatic retry was refused with the same code without calling the facilitator again, the resource was never served, and the operation remains unresolved with lastErrorCode SettlementFailure.",
      reason_codes: ["EXECUTION_OUTCOME_UNKNOWN"],
      settlement_invoked: true,
      resource_served: false,
    });
  });

  it("marks a classified final failure and still refuses an automatic retry", async () => {
    const context = await securityContext({
      reconciliation: true,
      classifySettlementError: () => "failed_final",
    });
    const facilitator = new FakeFacilitator({
      settle: () => ({ success: false, errorReason: "rejected_by_chain" }),
    });
    const server = new GuardedResourceServer(context, facilitator);
    const decision = await context.guard.authorise(honestInput);

    const outcome = await server.access({
      authorisationInput: honestInput,
      payload: paymentPayload({}),
      executionRef: "execution-A8-final",
      decision,
    });
    const retry = await server.access({
      authorisationInput: honestInput,
      payload: paymentPayload({}),
      executionRef: "execution-A8-final",
      decision,
    });

    expect(outcome).toMatchObject({ status: 402, reasonCodes: ["EXECUTION_FAILED_FINAL"] });
    expect(retry).toMatchObject({ status: 402, reasonCodes: ["EXECUTION_FAILED_FINAL"] });
    expect(facilitator.settleCalls).toHaveLength(1);
    expect(server.served).toBe(0);

    recordEvidence({
      id: "A8-final",
      attack: "Settlement failure classified as final by the integration",
      status: "PASS",
      expectation:
        "A final settlement failure must be recorded as final and must not be retried against the same authorisation.",
      observed:
        "EXECUTION_FAILED_FINAL on the first attempt and on the retry, with exactly one settlement call and no resource release.",
      reason_codes: ["EXECUTION_FAILED_FINAL"],
      settlement_invoked: true,
      resource_served: false,
    });
  });

  it("FINDING F-3: the guard does not require facilitator verification before settlement", async () => {
    const context = await securityContext({ reconciliation: true });
    const facilitator = new FakeFacilitator({
      verify: () => ({ isValid: false, invalidReason: "invalid_signature" }),
    });
    const decision = await context.guard.authorise(honestInput);

    // An integration that settles without calling verify first is not stopped
    // by the guard: settleIfAuthorised has no facilitator seam and no notion
    // of a verification result.
    const transaction = await context.guard.settleIfAuthorised(
      honestInput,
      decision,
      "execution-F3",
      async () => facilitator.settle(paymentPayload({}), honestRequirements).success,
    );

    expect(transaction).toBe(true);
    expect(facilitator.verifyCalls).toHaveLength(0);
    expect(facilitator.settleCalls).toHaveLength(1);

    recordEvidence({
      id: "A7-A8-F3",
      attack:
        "Settlement executed without a preceding facilitator verification (integration ordering)",
      status: "FAIL",
      expectation:
        "The guard should make verify-before-settle structurally unavoidable, so an integration cannot settle an unverified payment.",
      observed:
        "InntrisX402Guard.settleIfAuthorised accepts an opaque executor and has no facilitator seam. A caller that omits the verification step settles regardless; the facilitator's verify was never called. Verification ordering is documented but not enforced in code.",
      reason_codes: [],
      settlement_invoked: true,
      resource_served: false,
    });
  });
});

describe("A9 repeated resource access after one payment", () => {
  it("serves the resource once per authorisation and refuses further access", async () => {
    const context = await securityContext({ reconciliation: true });
    const facilitator = new FakeFacilitator();
    const server = new GuardedResourceServer(context, facilitator);
    const decision = await context.guard.authorise(honestInput);

    const first = await server.access({
      authorisationInput: honestInput,
      payload: paymentPayload({}),
      executionRef: "execution-A9-1",
      decision,
    });
    const second = await server.access({
      authorisationInput: honestInput,
      payload: paymentPayload({}),
      executionRef: "execution-A9-2",
      decision,
    });
    const third = await server.access({
      authorisationInput: honestInput,
      payload: paymentPayload({}),
      executionRef: "execution-A9-3",
      decision,
    });

    expect(first.status).toBe(200);
    expect(second).toMatchObject({ status: 402, reasonCodes: ["NONCE_ALREADY_CONSUMED"] });
    expect(third).toMatchObject({ status: 402, reasonCodes: ["NONCE_ALREADY_CONSUMED"] });
    expect(server.served).toBe(1);
    expect(facilitator.settleCalls).toHaveLength(1);

    recordEvidence({
      id: "A9",
      attack: "Repeated resource access using a single paid authorisation",
      status: "PASS",
      expectation:
        "One authorisation must yield at most one settled access; further attempts must be refused.",
      observed:
        "Three accesses with one decision: the first served, the second and third refused with NONCE_ALREADY_CONSUMED. One settlement call and one resource release in total.",
      reason_codes: ["NONCE_ALREADY_CONSUMED"],
      settlement_invoked: true,
      resource_served: true,
    });
  });
});

describe("A10 mismatched payment requirement versus signed payment", () => {
  it("refuses a payload bound to different requirements at authorisation and at settlement", async () => {
    const context = await securityContext();
    const divergent = paymentPayload({
      accepted: { ...honestRequirements, payTo: ATTACKER_PAYEE },
    });

    const bindingError = await Promise.resolve()
      .then(() => context.guard.authorise({ ...honestInput, paymentPayload: divergent }))
      .then(() => null)
      .catch((error: unknown) => error);

    const decision = await context.guard.authorise({
      ...honestInput,
      paymentPayload: paymentPayload({}),
    });
    const settle = vi.fn(async () => "settled");
    const settlementError = await context.guard
      .settleIfAuthorised(
        { ...honestInput, paymentPayload: divergent },
        decision,
        "execution-A10",
        settle,
      )
      .then(() => null)
      .catch((error: unknown) => error);

    expect(bindingError).toBeInstanceOf(X402BindingError);
    expect(settlementError).toBeInstanceOf(InntrisGuardError);
    expect((settlementError as InntrisGuardError).reasonCodes).toContain(
      "PAYMENT_REQUIREMENTS_MISMATCH",
    );
    expect(settle).not.toHaveBeenCalled();

    recordEvidence({
      id: "A10",
      attack: "Payment payload bound to different payment requirements than the ones being charged",
      status: "PASS",
      expectation:
        "A payload whose accepted requirements differ from the quoted requirements must never be authorised or settled.",
      observed: `Authorisation raised X402BindingError ("${(bindingError as Error).message}"). Settlement was refused with PAYMENT_REQUIREMENTS_MISMATCH and the executor was never called.`,
      reason_codes: ["PAYMENT_REQUIREMENTS_MISMATCH"],
      settlement_invoked: false,
      resource_served: false,
    });
  });

  it("refuses a payload introduced after a payload-free authorisation", async () => {
    const context = await securityContext();
    const decision = await context.guard.authorise(honestInput);
    const settle = vi.fn(async () => "settled");

    const error = await context.guard
      .settleIfAuthorised(
        { ...honestInput, paymentPayload: paymentPayload({}) },
        decision,
        "execution-A10-late",
        settle,
      )
      .then(() => null)
      .catch((thrown: unknown) => thrown);

    expect(error).toBeInstanceOf(InntrisGuardError);
    expect((error as InntrisGuardError).reasonCodes).toContain("ACTION_HASH_MISMATCH");
    expect(settle).not.toHaveBeenCalled();

    recordEvidence({
      id: "A10-late",
      attack: "Payment payload attached only after the decision was issued without one",
      status: "PASS",
      expectation:
        "The settled action must be byte-identical to the authorised action, including the presence or absence of a payload binding.",
      observed:
        "Adding a payload after a payload-free authorisation changes payment_payload_hash from null, so the action hash no longer matches. Settlement refused with ACTION_HASH_MISMATCH and the executor was never called.",
      reason_codes: ["ACTION_HASH_MISMATCH"],
      settlement_invoked: false,
      resource_served: false,
    });
  });

  it("FINDING F-4: the inner signed authorisation is bound but never cross-checked", async () => {
    const context = await securityContext({ reconciliation: true });
    // `accepted` matches the quoted requirements exactly, so every Inntris
    // binding check succeeds. The EIP-3009 authorisation the payer actually
    // signed pays a different address a different amount.
    const divergent = paymentPayload({
      to: ATTACKER_PAYEE,
      value: "1",
    });
    const input = { ...honestInput, paymentPayload: divergent };
    const decision = await context.guard.authorise(input);

    expect(decision.verdict).toBe("ALLOW");
    expect(decision.transaction.payee).toBe(honestRequirements.payTo);
    expect(decision.transaction.amount).toBe("4.50");

    const verification = await context.guard.verifyBeforeSettlement(input, decision);
    expect(verification.valid).toBe(true);

    // The honest facilitator is what catches this, not the adapter.
    const facilitator = new FakeFacilitator();
    const server = new GuardedResourceServer(context, facilitator);
    const outcome = await server.access({
      authorisationInput: input,
      payload: divergent,
      executionRef: "execution-F4",
      decision,
    });
    expect(outcome).toMatchObject({
      status: 402,
      reason: "invalid_exact_evm_payload_recipient_mismatch",
    });

    recordEvidence({
      id: "A10-F4",
      attack:
        "Signed EIP-3009 authorisation diverges from the accepted requirements it is presented with",
      status: "FAIL",
      expectation:
        "An Inntris ALLOW should attest that the payment actually signed pays the approved recipient the approved amount.",
      observed:
        "The adapter derives every policy field from `accepted` and binds `payload` only as an opaque hash. A payload whose inner authorisation pays 0x…ff a value of 1 produced a fully valid ALLOW for payee 0x…01 and amount 4.50, and verifyBeforeSettlement returned valid. Only the facilitator's own verification rejected it, with invalid_exact_evm_payload_recipient_mismatch.",
      reason_codes: [],
      settlement_invoked: false,
      resource_served: false,
    });
  });
});
