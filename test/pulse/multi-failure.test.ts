import { describe, expect, it } from "vitest";

import {
  calculateInputHash,
  canonicalHash,
  evaluateCase,
} from "../../packages/pulse-conformance-evaluator/src/index.js";
import { makeConformanceCase, makeMockVerifier } from "./helpers.js";

describe("Pulse evaluator failure collection", () => {
  it("deduplicates and orders every applicable controlled failure", async () => {
    const fixtureCase = await makeConformanceCase();
    fixtureCase.ap2.openMandate.constraints.push({
      type: "payment.future_constraint",
      value: true,
    });
    fixtureCase.ap2.verification.openMandateClaimsHash = canonicalHash(fixtureCase.ap2.openMandate);
    const verifier = makeMockVerifier(fixtureCase);
    fixtureCase.ap2.openMandate.iat -= 1;
    fixtureCase.x402.requirements.maxTimeoutSeconds = 360;
    fixtureCase.x402.payload.payload.authorization.validBefore = String(
      fixtureCase.nowEpochSeconds + 361,
    );
    fixtureCase.inputHash = calculateInputHash(fixtureCase);

    const result = await evaluateCase(fixtureCase, verifier);

    expect(result.failureCodes).toEqual([
      "AP2_OPEN_MANDATE_CLAIMS_HASH_MISMATCH",
      "AP2_UNSUPPORTED_CONSTRAINT",
      "AP2_X402_TIMEOUT_MISMATCH",
      "X402_ACCEPTED_REQUIREMENTS_MISMATCH",
      "EIP3009_VALIDITY_EXCEEDS_TIMEOUT",
      "EIP3009_VALIDITY_EXCEEDS_AP2_EXPIRY",
      "EIP3009_SIGNATURE_INVALID",
    ]);
    expect(new Set(result.failureCodes).size).toBe(result.failureCodes.length);
  });
});
