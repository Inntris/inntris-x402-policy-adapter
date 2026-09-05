import { describe, expect, it } from "vitest";

import {
  calculateInputHash,
  evaluateCase,
} from "../../packages/pulse-conformance-evaluator/src/index.js";
import { makeConformanceCase, makeMockVerifier } from "./helpers.js";

describe("Pulse evaluator negative paths", () => {
  it("rejects a payment amount substituted after acceptance", async () => {
    const fixtureCase = await makeConformanceCase();
    const verifier = makeMockVerifier(fixtureCase);
    fixtureCase.x402.requirements.amount = "1250001";
    fixtureCase.inputHash = calculateInputHash(fixtureCase);

    const result = await evaluateCase(fixtureCase, verifier);

    expect(result.decision).toBe("reject");
    expect(result.failureCodes).toEqual([
      "AP2_X402_AMOUNT_MISMATCH",
      "X402_ACCEPTED_REQUIREMENTS_MISMATCH",
      "EIP3009_VALUE_MISMATCH",
    ]);
  });

  it("reports only independently evaluated AP2 stage failures", async () => {
    const fixtureCase = await makeConformanceCase();
    const verifier = {
      verify: async () => ({
        version: "inntris-pulse-ap2-structured-verification/0.1" as const,
        sdk: {
          repository: "https://github.com/google-agentic-commerce/AP2",
          commit: fixtureCase.sourcePins.ap2Commit,
          protocolVersion: "0.2",
        },
        openMandate: { status: "invalid" as const },
        closedMandate: { status: "invalid" as const },
        keyBinding: { status: "invalid" as const },
        mandateTime: { status: "notEvaluated" as const },
        receipt: { status: "invalid" as const },
      }),
    };

    const result = await evaluateCase(fixtureCase, verifier);

    expect(result.failureCodes).toEqual([
      "AP2_CLOSED_MANDATE_UNVERIFIED",
      "AP2_OPEN_MANDATE_UNVERIFIED",
      "AP2_KEY_BINDING_UNVERIFIED",
      "AP2_RECEIPT_UNVERIFIED",
    ]);
  });

  it("uses the aggregate code only when the structured bridge itself fails", async () => {
    const fixtureCase = await makeConformanceCase();
    const result = await evaluateCase(fixtureCase, {
      verify: async () => {
        throw new Error("synthetic bridge failure");
      },
    });

    expect(result.failureCodes).toEqual(["AP2_CRYPTOGRAPHIC_EVIDENCE_INVALID"]);
  });

  it("does not cascade an invalid AP2 stage into stages that were not evaluated", async () => {
    const fixtureCase = await makeConformanceCase();
    const baselineVerifier = makeMockVerifier(fixtureCase);
    const baseline = await baselineVerifier.verify(
      {} as Parameters<typeof baselineVerifier.verify>[0],
    );

    const rootFailure = await evaluateCase(fixtureCase, {
      verify: async () => ({
        ...baseline,
        openMandate: { status: "invalid" as const },
        closedMandate: { status: "notEvaluated" as const },
        keyBinding: { status: "notEvaluated" as const },
        mandateTime: { status: "notEvaluated" as const },
      }),
    });
    expect(rootFailure.failureCodes).toEqual(["AP2_OPEN_MANDATE_UNVERIFIED"]);

    const bindingFailure = await evaluateCase(fixtureCase, {
      verify: async () => ({
        ...baseline,
        keyBinding: { status: "invalid" as const },
      }),
    });
    expect(bindingFailure.failureCodes).toEqual(["AP2_KEY_BINDING_UNVERIFIED"]);

    const receiptFailure = await evaluateCase(fixtureCase, {
      verify: async () => ({
        ...baseline,
        receipt: { status: "invalid" as const },
      }),
    });
    expect(receiptFailure.failureCodes).toEqual(["AP2_RECEIPT_UNVERIFIED"]);
  });
});
