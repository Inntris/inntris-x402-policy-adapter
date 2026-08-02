import {
  X402SandboxProbeError,
  probeX402Sandbox,
  type X402SandboxProbeClient,
} from "@inntris/x402-adapter";
import { describe, expect, it, vi } from "vitest";

const supported = {
  kinds: [{ x402Version: 2, scheme: "exact", network: "eip155:84532" }],
  extensions: [],
  signers: {},
} satisfies Awaited<ReturnType<X402SandboxProbeClient["getSupported"]>>;

function client(overrides: Partial<X402SandboxProbeClient> = {}): X402SandboxProbeClient {
  return {
    getSupported: vi.fn(async () => supported),
    verify: vi.fn(async () => ({
      isValid: false,
      invalidReason: "invalid_exact_evm_payload_signature",
    })),
    ...overrides,
  };
}

describe("official x402 sandbox probe", () => {
  it("requires advertised v2 exact support and a rejected invalid payment", async () => {
    const probeClient = client();
    const report = await probeX402Sandbox({
      client: probeClient,
      now: new Date("2026-08-02T12:00:00.000Z"),
    });

    expect(report).toEqual({
      version: "inntris-x402-sandbox-probe-v1",
      facilitator_url: "https://x402.org/facilitator",
      x402_version: 2,
      scheme: "exact",
      network: "eip155:84532",
      supported: true,
      invalid_payment_rejected: true,
      invalid_reason: "invalid_exact_evm_payload_signature",
      observed_at: "2026-08-02T12:00:00.000Z",
    });
    expect(probeClient.verify).toHaveBeenCalledOnce();
    expect(vi.mocked(probeClient.verify).mock.calls[0]?.[0]).toMatchObject({
      x402Version: 2,
      accepted: {
        scheme: "exact",
        network: "eip155:84532",
        amount: "1",
      },
    });
  });

  it("fails when the required sandbox mechanism is not advertised", async () => {
    const probeClient = client({
      getSupported: vi.fn(async () => ({ kinds: [], extensions: [], signers: {} })),
    });

    await expect(probeX402Sandbox({ client: probeClient })).rejects.toThrow(
      "does not advertise x402 v2 exact",
    );
    expect(probeClient.verify).not.toHaveBeenCalled();
  });

  it("fails if the facilitator accepts the invalid payment", async () => {
    const probeClient = client({
      verify: vi.fn(async () => ({ isValid: true })),
    });

    await expect(probeX402Sandbox({ client: probeClient })).rejects.toBeInstanceOf(
      X402SandboxProbeError,
    );
  });

  it("rejects insecure or credential-bearing facilitator URLs", async () => {
    await expect(
      probeX402Sandbox({ facilitatorUrl: "http://x402.org/facilitator", client: client() }),
    ).rejects.toThrow("must use HTTPS");
    await expect(
      probeX402Sandbox({
        facilitatorUrl: "https://user:secret@x402.org/facilitator",
        client: client(),
      }),
    ).rejects.toThrow("must not contain credentials");
    await expect(
      probeX402Sandbox({
        facilitatorUrl: "https://x402.org/facilitator?redirect=unexpected",
        client: client(),
      }),
    ).rejects.toThrow("must not contain query or fragment data");
  });
});
