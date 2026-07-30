import {
  attachDecisionSignature,
  calculateDecisionFingerprint,
  createPublicDemoSigner,
  signableDecisionPayload,
  verifyDecisionSignature,
} from "@inntris/decision-core";
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

  it("rejects a decision whose restated subject differs from the supplied action", async () => {
    const context = await testContext();
    const action = actionFromX402(bindingInput);
    const decision = await context.provider.evaluate(action);

    /**
     * An issuer bug, rather than a tamper, can restate a subject that
     * disagrees with the action it hashed. The signature and the action hash
     * both still pass, so only the binding check catches it.
     */
    const inconsistent = structuredClone(decision);
    inconsistent.transaction.payee = "0x0000000000000000000000000000000000000002";
    const resigned = await attachDecisionSignature(
      signableDecisionPayload({
        ...inconsistent,
        decision_fingerprint: calculateDecisionFingerprint(inconsistent),
      }),
      createPublicDemoSigner(),
    );

    const result = verifyDecision({
      decision: resigned,
      action,
      keyRegistry: context.keyRegistry,
      at: context.clock.now(),
    });

    expect(result.checks.signature).toBe(true);
    expect(result.checks.action_hash).toBe(true);
    expect(result.checks.decision_binding).toBe(false);
    expect(result.reason_codes).toContain("DECISION_BINDING_MISMATCH");
    expect(result.valid).toBe(false);
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
