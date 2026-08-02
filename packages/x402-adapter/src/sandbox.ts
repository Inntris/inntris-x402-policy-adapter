import { HTTPFacilitatorClient } from "@x402/core/server";
import {
  VerifyError,
  type PaymentPayload,
  type PaymentRequirements,
  type SupportedResponse,
  type VerifyResponse,
} from "@x402/core/types";

export const OFFICIAL_X402_TESTNET_FACILITATOR = "https://x402.org/facilitator";
export const X402_SANDBOX_NETWORK = "eip155:84532";
export const X402_SANDBOX_SCHEME = "exact";

const BASE_SEPOLIA_USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const PROBE_PAYER = "0x0000000000000000000000000000000000000002";
const PROBE_PAYEE = "0x0000000000000000000000000000000000000001";

export interface X402SandboxProbeClient {
  getSupported: () => Promise<SupportedResponse>;
  verify: (
    paymentPayload: PaymentPayload,
    paymentRequirements: PaymentRequirements,
  ) => Promise<VerifyResponse>;
}

export interface X402SandboxProbeOptions {
  facilitatorUrl?: string | undefined;
  client?: X402SandboxProbeClient | undefined;
  now?: Date | undefined;
}

export interface X402SandboxProbeReport {
  version: "inntris-x402-sandbox-probe-v1";
  facilitator_url: string;
  x402_version: 2;
  scheme: "exact";
  network: "eip155:84532";
  supported: true;
  invalid_payment_rejected: true;
  invalid_reason: string;
  observed_at: string;
}

export class X402SandboxProbeError extends Error {
  override readonly name = "X402SandboxProbeError";
}

function validatedFacilitatorUrl(input: string): string {
  const url = new URL(input);
  if (url.protocol !== "https:") {
    throw new X402SandboxProbeError("The x402 sandbox facilitator URL must use HTTPS");
  }
  if (url.username !== "" || url.password !== "") {
    throw new X402SandboxProbeError(
      "The x402 sandbox facilitator URL must not contain credentials",
    );
  }
  if (url.search !== "" || url.hash !== "") {
    throw new X402SandboxProbeError(
      "The x402 sandbox facilitator URL must not contain query or fragment data",
    );
  }
  url.pathname = url.pathname.replace(/\/+$/, "");
  return url.toString().replace(/\/$/, "");
}

function invalidProbePayment(now: Date): {
  paymentPayload: PaymentPayload;
  paymentRequirements: PaymentRequirements;
} {
  const paymentRequirements = {
    scheme: X402_SANDBOX_SCHEME,
    network: X402_SANDBOX_NETWORK,
    amount: "1",
    asset: BASE_SEPOLIA_USDC,
    payTo: PROBE_PAYEE,
    maxTimeoutSeconds: 60,
    extra: {
      name: "USDC",
      version: "2",
    },
  } satisfies PaymentRequirements;
  return {
    paymentRequirements,
    paymentPayload: {
      x402Version: 2,
      resource: {
        url: "https://example.test/inntris-x402-sandbox-probe",
        description: "Deliberately invalid Inntris facilitator verification probe",
        mimeType: "application/json",
      },
      accepted: paymentRequirements,
      payload: {
        signature: `0x${"00".repeat(65)}`,
        authorization: {
          from: PROBE_PAYER,
          to: PROBE_PAYEE,
          value: "1",
          validAfter: "0",
          validBefore: String(Math.floor(now.getTime() / 1000) + 300),
          nonce: `0x${"00".repeat(32)}`,
        },
      },
    },
  };
}

export async function probeX402Sandbox(
  options: X402SandboxProbeOptions = {},
): Promise<X402SandboxProbeReport> {
  const facilitatorUrl = validatedFacilitatorUrl(
    options.facilitatorUrl ?? OFFICIAL_X402_TESTNET_FACILITATOR,
  );
  const client = options.client ?? new HTTPFacilitatorClient({ url: facilitatorUrl });
  const now = options.now ?? new Date();
  const supported = await client.getSupported();
  const supportsExactBaseSepolia = supported.kinds.some(
    (kind) =>
      kind.x402Version === 2 &&
      kind.scheme === X402_SANDBOX_SCHEME &&
      kind.network === X402_SANDBOX_NETWORK,
  );
  if (!supportsExactBaseSepolia) {
    throw new X402SandboxProbeError(
      "The facilitator does not advertise x402 v2 exact on Base Sepolia",
    );
  }

  const { paymentPayload, paymentRequirements } = invalidProbePayment(now);
  let invalidReason: string;
  try {
    const verification = await client.verify(paymentPayload, paymentRequirements);
    if (verification.isValid) {
      throw new X402SandboxProbeError(
        "The facilitator accepted the deliberately invalid unsigned payment",
      );
    }
    invalidReason = verification.invalidReason ?? "invalid_payment";
  } catch (error) {
    if (!(error instanceof VerifyError)) {
      throw error;
    }
    invalidReason = error.invalidReason ?? "invalid_payment";
  }

  return {
    version: "inntris-x402-sandbox-probe-v1",
    facilitator_url: facilitatorUrl,
    x402_version: 2,
    scheme: X402_SANDBOX_SCHEME,
    network: X402_SANDBOX_NETWORK,
    supported: true,
    invalid_payment_rejected: true,
    invalid_reason: invalidReason,
    observed_at: now.toISOString(),
  };
}
