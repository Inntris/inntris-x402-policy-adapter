import { privateKeyToAccount } from "viem/accounts";
import { describe, expect, it } from "vitest";

import {
  EIP3009_AUTHORIZATION_TYPES,
  calculateInputHash,
  canonicalHash,
  evaluateCase,
  type PaymentInstrument,
} from "../../packages/pulse-conformance-evaluator/src/index.js";
import { makeConformanceCase, makeMockVerifier } from "./helpers.js";

const OTHER_REFERENCE = `${"C".repeat(42)}A`;
const OTHER_PAY_TO = "0x000000000000000000000000000000000000bEEF";

describe("Pulse diagnostic failure derivation", () => {
  it("checks normalised checkout and receipt references without downgrading the signatures", async () => {
    const fixtureCase = await makeConformanceCase();
    const verifier = makeMockVerifier(fixtureCase);
    const reference = fixtureCase.ap2.openMandate.constraints.find(
      (constraint) => constraint.type === "payment.reference",
    );
    if (reference === undefined || !("conditional_transaction_id" in reference)) {
      throw new Error("Test payment reference setup failed");
    }
    reference.conditional_transaction_id = OTHER_REFERENCE;
    const receipt = fixtureCase.ap2.paymentReceipt;
    if (receipt === undefined) throw new Error("Test receipt setup failed");
    receipt.reference = OTHER_REFERENCE;
    fixtureCase.ap2.verification.openMandateClaimsHash = canonicalHash(fixtureCase.ap2.openMandate);
    fixtureCase.inputHash = calculateInputHash(fixtureCase);

    const result = await evaluateCase(fixtureCase, verifier);

    expect(result).toEqual({
      id: "independent-test-case",
      decision: "reject",
      failureCodes: [
        "AP2_CHECKOUT_BINDING_UNVERIFIED",
        "AP2_PAYMENT_REFERENCE_MISMATCH",
        "AP2_CONSTRAINT_VIOLATION",
        "AP2_RECEIPT_REFERENCE_MISMATCH",
      ],
    });
  });

  it("reports a normalised receipt transaction disagreement as a binding failure", async () => {
    const fixtureCase = await makeConformanceCase();
    const verifier = makeMockVerifier(fixtureCase);
    const receipt = fixtureCase.ap2.paymentReceipt;
    if (receipt === undefined) throw new Error("Test receipt setup failed");
    receipt.network_confirmation_id = `0x${"34".repeat(32)}`;
    fixtureCase.inputHash = calculateInputHash(fixtureCase);

    await expect(evaluateCase(fixtureCase, verifier)).resolves.toEqual({
      id: "independent-test-case",
      decision: "reject",
      failureCodes: ["AP2_RECEIPT_TRANSACTION_MISMATCH"],
    });
  });

  it("rejects a selected instrument whose type is not x402", async () => {
    const fixtureCase = await makeConformanceCase();
    const selected = fixtureCase.ap2.closedMandate.payment_instrument;
    const instrumentConstraint = fixtureCase.ap2.openMandate.constraints.find(
      (constraint) => constraint.type === "payment.allowed_payment_instruments",
    );
    const allowedInstrument =
      instrumentConstraint === undefined || !("allowed" in instrumentConstraint)
        ? undefined
        : (instrumentConstraint.allowed[0] as PaymentInstrument | undefined);
    if (allowedInstrument === undefined) throw new Error("Test instrument setup failed");
    selected.type = "card";
    allowedInstrument.type = "card";
    fixtureCase.ap2.verification.openMandateClaimsHash = canonicalHash(fixtureCase.ap2.openMandate);
    fixtureCase.ap2.verification.closedMandateClaimsHash = canonicalHash(
      fixtureCase.ap2.closedMandate,
    );
    fixtureCase.inputHash = calculateInputHash(fixtureCase);

    await expect(evaluateCase(fixtureCase, makeMockVerifier(fixtureCase))).resolves.toEqual({
      id: "independent-test-case",
      decision: "reject",
      failureCodes: ["AP2_PAYMENT_INSTRUMENT_NOT_ALLOWED"],
    });
  });

  it("evaluates every normalised instrument constraint independently", async () => {
    const fixtureCase = await makeConformanceCase();
    const verifier = makeMockVerifier(fixtureCase);
    const selected = fixtureCase.ap2.closedMandate.payment_instrument;
    fixtureCase.ap2.openMandate.constraints.push(
      {
        type: "payment.allowed_payment_instruments",
        allowed: [
          {
            id: selected.id,
            type: selected.type,
            description: selected.description,
          },
        ],
      },
      {
        type: "payment.amount_range",
        currency: fixtureCase.ap2.closedMandate.payment_amount.currency,
        min: fixtureCase.ap2.closedMandate.payment_amount.amount + 1,
        max: fixtureCase.ap2.closedMandate.payment_amount.amount + 10,
      },
    );
    fixtureCase.ap2.verification.openMandateClaimsHash = canonicalHash(fixtureCase.ap2.openMandate);
    fixtureCase.inputHash = calculateInputHash(fixtureCase);

    await expect(evaluateCase(fixtureCase, verifier)).resolves.toEqual({
      id: "independent-test-case",
      decision: "reject",
      failureCodes: ["AP2_CONSTRAINT_VIOLATION", "AP2_PAYMENT_INSTRUMENT_NOT_ALLOWED"],
    });
  });

  it("links the AP2 merchant identity and x402 recipient under both payee codes", async () => {
    const fixtureCase = await makeConformanceCase();
    const verifier = makeMockVerifier(fixtureCase);
    const closedExtension = fixtureCase.ap2.closedMandate.payment_instrument.x402;
    const instrumentConstraint = fixtureCase.ap2.openMandate.constraints.find(
      (constraint) => constraint.type === "payment.allowed_payment_instruments",
    );
    const allowedInstrument =
      instrumentConstraint === undefined || !("allowed" in instrumentConstraint)
        ? undefined
        : (instrumentConstraint.allowed[0] as PaymentInstrument | undefined);
    if (closedExtension === undefined || allowedInstrument?.x402 === undefined) {
      throw new Error("Test instrument setup failed");
    }
    closedExtension.ap2PayeeId = "different-merchant";
    allowedInstrument.x402.ap2PayeeId = "different-merchant";
    fixtureCase.ap2.verification.openMandateClaimsHash = canonicalHash(fixtureCase.ap2.openMandate);
    fixtureCase.ap2.verification.closedMandateClaimsHash = canonicalHash(
      fixtureCase.ap2.closedMandate,
    );
    fixtureCase.inputHash = calculateInputHash(fixtureCase);

    await expect(evaluateCase(fixtureCase, verifier)).resolves.toEqual({
      id: "independent-test-case",
      decision: "reject",
      failureCodes: ["AP2_X402_PAYEE_MISMATCH", "AP2_X402_COMMERCE_BINDING_MISMATCH"],
    });
  });

  it("rejects an AP2 x402 recipient that differs from the requirements", async () => {
    const fixtureCase = await makeConformanceCase();
    const closedExtension = fixtureCase.ap2.closedMandate.payment_instrument.x402;
    const instrumentConstraint = fixtureCase.ap2.openMandate.constraints.find(
      (constraint) => constraint.type === "payment.allowed_payment_instruments",
    );
    const allowedInstrument =
      instrumentConstraint === undefined || !("allowed" in instrumentConstraint)
        ? undefined
        : (instrumentConstraint.allowed[0] as PaymentInstrument | undefined);
    if (closedExtension === undefined || allowedInstrument?.x402 === undefined) {
      throw new Error("Test instrument setup failed");
    }
    closedExtension.payTo = OTHER_PAY_TO;
    allowedInstrument.x402.payTo = OTHER_PAY_TO;
    fixtureCase.ap2.verification.openMandateClaimsHash = canonicalHash(fixtureCase.ap2.openMandate);
    fixtureCase.ap2.verification.closedMandateClaimsHash = canonicalHash(
      fixtureCase.ap2.closedMandate,
    );
    fixtureCase.inputHash = calculateInputHash(fixtureCase);

    await expect(evaluateCase(fixtureCase, makeMockVerifier(fixtureCase))).resolves.toEqual({
      id: "independent-test-case",
      decision: "reject",
      failureCodes: ["AP2_X402_PAYEE_MISMATCH"],
    });
  });

  it("keeps unsupported AP2 constraints separate from the timeout edge", async () => {
    const fixtureCase = await makeConformanceCase();
    const verifier = makeMockVerifier(fixtureCase);
    fixtureCase.ap2.openMandate.constraints.push({
      type: "payment.budget",
      currency: "GBP",
      max: 1250,
    });
    fixtureCase.x402.requirements.maxTimeoutSeconds = 301;
    fixtureCase.x402.payload.accepted.maxTimeoutSeconds = 301;
    fixtureCase.ap2.verification.openMandateClaimsHash = canonicalHash(fixtureCase.ap2.openMandate);
    fixtureCase.inputHash = calculateInputHash(fixtureCase);

    await expect(evaluateCase(fixtureCase, verifier)).resolves.toEqual({
      id: "independent-test-case",
      decision: "reject",
      failureCodes: ["AP2_UNSUPPORTED_CONSTRAINT", "AP2_X402_TIMEOUT_MISMATCH"],
    });
  });

  it("does not cascade an accepted requirements change into an AP2 edge", async () => {
    const fixtureCase = await makeConformanceCase();
    fixtureCase.x402.payload.accepted.scheme = "different-exact-profile";
    fixtureCase.x402.payload.extensions = { unknownFixtureExtension: true };
    fixtureCase.inputHash = calculateInputHash(fixtureCase);

    await expect(evaluateCase(fixtureCase, makeMockVerifier(fixtureCase))).resolves.toEqual({
      id: "independent-test-case",
      decision: "reject",
      failureCodes: ["X402_ACCEPTED_REQUIREMENTS_MISMATCH", "X402_UNSUPPORTED_EXTENSION"],
    });
  });

  it("uses normalised preset and receipt fields for their specific failures", async () => {
    const fixtureCase = await makeConformanceCase();
    const verifier = makeMockVerifier(fixtureCase);
    fixtureCase.ap2.openMandate.payee = {
      id: "different-merchant",
      name: "Different merchant",
      website: "https://different.example",
    };
    const receipt = fixtureCase.ap2.paymentReceipt;
    if (receipt === undefined) throw new Error("Test receipt setup failed");
    receipt.status = "Error";
    receipt.error = "synthetic_error";
    receipt.error_description = "Independent synthetic failure";
    delete receipt.network_confirmation_id;
    fixtureCase.ap2.verification.openMandateClaimsHash = canonicalHash(fixtureCase.ap2.openMandate);
    fixtureCase.inputHash = calculateInputHash(fixtureCase);

    await expect(evaluateCase(fixtureCase, verifier)).resolves.toEqual({
      id: "independent-test-case",
      decision: "reject",
      failureCodes: [
        "AP2_OPEN_PRESET_MISMATCH",
        "AP2_RECEIPT_NOT_SUCCESSFUL",
        "AP2_RECEIPT_TRANSACTION_MISMATCH",
      ],
    });
  });

  it("does not use a valid signed closed claim as a fallback for the normalised transaction", async () => {
    const fixtureCase = await makeConformanceCase();
    const verifier = makeMockVerifier(fixtureCase);
    fixtureCase.ap2.closedMandate.transaction_id = OTHER_REFERENCE;
    fixtureCase.ap2.verification.closedMandateClaimsHash = canonicalHash(
      fixtureCase.ap2.closedMandate,
    );
    fixtureCase.inputHash = calculateInputHash(fixtureCase);

    await expect(evaluateCase(fixtureCase, verifier)).resolves.toEqual({
      id: "independent-test-case",
      decision: "reject",
      failureCodes: ["AP2_CHECKOUT_BINDING_UNVERIFIED", "AP2_CLOSED_TRANSACTION_ID_MISMATCH"],
    });
  });

  it("does not turn an authorization payer mismatch into a settlement payer failure", async () => {
    const fixtureCase = await makeConformanceCase();
    const account = privateKeyToAccount(
      "0x0000000000000000000000000000000000000000000000000000000000000002",
    );
    const authorization = fixtureCase.x402.payload.payload.authorization;
    authorization.from = account.address;
    fixtureCase.x402.settlement.payer = account.address;
    fixtureCase.x402.payload.payload.signature = await account.signTypedData({
      domain: {
        name: fixtureCase.x402.requirements.extra.name,
        version: fixtureCase.x402.requirements.extra.version,
        chainId: 31337n,
        verifyingContract: fixtureCase.x402.requirements.asset,
      },
      types: EIP3009_AUTHORIZATION_TYPES,
      primaryType: "TransferWithAuthorization",
      message: {
        from: account.address,
        to: authorization.to,
        value: BigInt(authorization.value),
        validAfter: BigInt(authorization.validAfter),
        validBefore: BigInt(authorization.validBefore),
        nonce: authorization.nonce,
      },
    });
    fixtureCase.inputHash = calculateInputHash(fixtureCase);

    await expect(evaluateCase(fixtureCase, makeMockVerifier(fixtureCase))).resolves.toEqual({
      id: "independent-test-case",
      decision: "reject",
      failureCodes: ["EIP3009_PAYER_MISMATCH"],
    });
  });
});
