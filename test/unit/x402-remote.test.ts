import {
  InntrisGuardError,
  InntrisX402Guard,
  RemoteInntrisDecisionProvider,
  actionFromX402,
  formatAtomicAmount,
  paymentRequirementsHash,
} from "@inntris/x402-adapter";
import { describe, expect, it, vi } from "vitest";

import { bindingInput, testContext } from "../helpers.js";

describe("official x402 binding and remote failure", () => {
  it("formats atomic amounts into canonical decimal strings", () => {
    expect(formatAtomicAmount("4500000", 6)).toBe("4.50");
    expect(formatAtomicAmount("1", 6)).toBe("0.000001");
    expect(formatAtomicAmount("1000000", 6)).toBe("1.00");
  });

  it("binds the official payment requirements to the action", () => {
    const action = actionFromX402(bindingInput);
    expect(action.protocol_reference.payment_requirements_hash).toBe(
      paymentRequirementsHash(bindingInput.paymentRequirements),
    );
  });

  it("binds a supplied x402 payment payload and rejects a mismatched challenge", () => {
    const paymentPayload = {
      x402Version: 2,
      accepted: bindingInput.paymentRequirements,
      payload: { signature: "public-test-payload" },
    };
    const action = actionFromX402({ ...bindingInput, paymentPayload });
    expect(action.protocol_reference.payment_payload_hash).toMatch(/^sha256:[0-9a-f]{64}$/u);
    expect(() =>
      actionFromX402({
        ...bindingInput,
        paymentPayload: {
          ...paymentPayload,
          accepted: { ...bindingInput.paymentRequirements, amount: "5500000" },
        },
      }),
    ).toThrow("different x402 payment requirements");
  });

  it("fails closed when remote Inntris is unavailable", async () => {
    const context = await testContext();
    const remote = new RemoteInntrisDecisionProvider({
      apiUrl: "https://api.example.test",
      apiKey: "not-a-real-key",
      keyRegistry: context.keyRegistry,
      fetchImplementation: vi.fn(async () => {
        throw new Error("offline");
      }),
    });
    const guard = new InntrisX402Guard({
      provider: remote,
      keyRegistry: context.keyRegistry,
      clock: context.clock,
    });
    await expect(guard.authorise(bindingInput)).rejects.toBeInstanceOf(InntrisGuardError);
  });
});
