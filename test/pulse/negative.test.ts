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

  it("fails closed when the AP2 cryptographic verifier rejects every stage", async () => {
    const fixtureCase = await makeConformanceCase();
    const verifier = {
      verify: async () => ({
        version: "inntris-pulse-ap2-structured-verification/0.1" as const,
        sdk: {
          repository: "https://github.com/google-agentic-commerce/AP2",
          commit: fixtureCase.sourcePins.ap2Commit,
          protocolVersion: "0.2",
        },
        openMandate: { verified: false },
        closedMandate: { verified: false },
        keyBinding: { verified: false },
        receipt: { verified: false },
      }),
    };

    const result = await evaluateCase(fixtureCase, verifier);

    expect(result.failureCodes.slice(0, 5)).toEqual([
      "AP2_CRYPTOGRAPHIC_EVIDENCE_INVALID",
      "AP2_CLOSED_MANDATE_UNVERIFIED",
      "AP2_OPEN_MANDATE_UNVERIFIED",
      "AP2_KEY_BINDING_UNVERIFIED",
      "AP2_RECEIPT_UNVERIFIED",
    ]);
  });
});
