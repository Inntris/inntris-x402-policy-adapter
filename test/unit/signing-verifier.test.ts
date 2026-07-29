import { verifyDecisionSignature } from "@inntris/decision-core";
import { verifyDecision } from "@inntris/decision-verifier";
import { actionFromX402 } from "@inntris/x402-adapter";
import { describe, expect, it } from "vitest";

import { bindingInput, testContext } from "../helpers.js";

describe("decision signing and offline verification", () => {
  it("verifies a valid Ed25519 decision", async () => {
    const context = await testContext();
    const decision = await context.guard.authorise(bindingInput);
    expect(
      verifyDecisionSignature(
        decision,
        Buffer.from(context.keyRegistry.keys[0]!.public_key, "base64url"),
      ),
    ).toBe(true);
    expect(
      verifyDecision({
        decision,
        action: actionFromX402(bindingInput),
        keyRegistry: context.keyRegistry,
        at: context.clock.now(),
        expectedPolicyVersion: "1",
      }).valid,
    ).toBe(true);
  });

  it("rejects a changed verdict", async () => {
    const context = await testContext();
    const decision = await context.guard.authorise(bindingInput);
    const changed = { ...decision, verdict: "BLOCK" as const };
    const result = verifyDecision({
      decision: changed,
      action: actionFromX402(bindingInput),
      keyRegistry: context.keyRegistry,
      at: context.clock.now(),
    });
    expect(result.valid).toBe(false);
    expect(result.reason_codes).toContain("INVALID_SIGNATURE");
    expect(result.reason_codes).toContain("FINGERPRINT_MISMATCH");
  });

  it("rejects a changed reason code", async () => {
    const context = await testContext();
    const decision = await context.guard.authorise(bindingInput);
    const changed = { ...decision, reason_codes: ["DEFAULT_DENY"] as const };
    const result = verifyDecision({
      decision: changed,
      action: actionFromX402(bindingInput),
      keyRegistry: context.keyRegistry,
      at: context.clock.now(),
    });
    expect(result.valid).toBe(false);
    expect(result.reason_codes).toContain("INVALID_SIGNATURE");
  });

  it("does not access the network in offline mode", async () => {
    const originalFetch = globalThis.fetch;
    let networkCalls = 0;
    globalThis.fetch = () => {
      networkCalls += 1;
      throw new Error("network disabled");
    };
    try {
      const context = await testContext();
      const decision = await context.guard.authorise(bindingInput);
      const result = verifyDecision({
        decision,
        action: actionFromX402(bindingInput),
        keyRegistry: context.keyRegistry,
        at: context.clock.now(),
      });
      expect(result.valid).toBe(true);
      expect(networkCalls).toBe(0);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
