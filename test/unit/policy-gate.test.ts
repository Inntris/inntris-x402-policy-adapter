import { InntrisGuardError } from "@inntris/x402-adapter";
import { describe, expect, it, vi } from "vitest";

import { bindingInput, testContext } from "../helpers.js";

describe("policy and execution gate", () => {
  it("prevents expired decisions from executing", async () => {
    const context = await testContext();
    const decision = await context.guard.authorise(bindingInput);
    context.clock.advance(61_000);
    const settle = vi.fn(async () => "settled");
    await expect(
      context.guard.settleIfAuthorised(bindingInput, decision, "expiry", settle),
    ).rejects.toMatchObject({ reasonCodes: ["DECISION_EXPIRED"] });
    expect(settle).not.toHaveBeenCalled();
  });

  it.each([
    ["BLOCK", "150000000"],
    ["REQUIRE_APPROVAL", "80000000"],
  ])("prevents %s decisions from executing", async (verdict, amount) => {
    const context = await testContext();
    const input = {
      ...bindingInput,
      paymentRequirements: { ...bindingInput.paymentRequirements, amount },
    };
    const decision = await context.guard.authorise(input);
    expect(decision.verdict).toBe(verdict);
    const settle = vi.fn(async () => "settled");
    await expect(
      context.guard.settleIfAuthorised(input, decision, `execution-${verdict}`, settle),
    ).rejects.toBeInstanceOf(InntrisGuardError);
    expect(settle).not.toHaveBeenCalled();
  });

  it("never settles after action verification failure", async () => {
    const context = await testContext();
    const decision = await context.guard.authorise(bindingInput);
    const tampered = {
      ...bindingInput,
      paymentRequirements: {
        ...bindingInput.paymentRequirements,
        payTo: "0x0000000000000000000000000000000000000002",
      },
    };
    const settle = vi.fn(async () => "settled");
    await expect(
      context.guard.settleIfAuthorised(tampered, decision, "tamper", settle),
    ).rejects.toBeInstanceOf(InntrisGuardError);
    expect(settle).not.toHaveBeenCalled();
  });
});
