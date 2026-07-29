import { InntrisActionV1Schema, hashCanonical, type InntrisActionV1 } from "@inntris/decision-core";
import { PaymentPayloadV2Schema, PaymentRequirementsV2Schema } from "@x402/core/schemas";
import type { PaymentPayload, PaymentRequirements } from "@x402/core/types";

export interface X402BindingInput {
  paymentRequirements: PaymentRequirements;
  paymentPayload?: PaymentPayload;
  resource: string;
  principalId: string;
  agentId: string;
  purpose: string;
  assetDecimals: number;
}

export class X402BindingError extends Error {
  override readonly name = "X402BindingError";
}

export function normalisePaymentRequirements(input: PaymentRequirements): PaymentRequirements {
  const parsed = PaymentRequirementsV2Schema.parse(input);
  return {
    scheme: parsed.scheme,
    network: parsed.network as PaymentRequirements["network"],
    asset: parsed.asset,
    amount: parsed.amount,
    payTo: parsed.payTo,
    maxTimeoutSeconds: parsed.maxTimeoutSeconds,
    extra: parsed.extra ?? {},
  };
}

export function normalisePaymentPayload(input: PaymentPayload): PaymentPayload {
  const parsed = PaymentPayloadV2Schema.parse(input);
  const normalised = {
    ...parsed,
    accepted: normalisePaymentRequirements(parsed.accepted as PaymentRequirements),
  };
  return JSON.parse(JSON.stringify(normalised)) as PaymentPayload;
}

export function paymentRequirementsHash(requirements: PaymentRequirements): string {
  return hashCanonical(normalisePaymentRequirements(requirements));
}

export function paymentPayloadHash(payload: PaymentPayload): string {
  return hashCanonical(normalisePaymentPayload(payload));
}

export function formatAtomicAmount(amount: string, decimals: number): string {
  if (!/^(0|[1-9]\d*)$/u.test(amount)) {
    throw new X402BindingError("x402 amount must be an unsigned atomic-unit integer string");
  }
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 18) {
    throw new X402BindingError("assetDecimals must be an integer from 0 to 18");
  }

  const padded = amount.padStart(decimals + 1, "0");
  const whole = decimals === 0 ? padded : padded.slice(0, -decimals);
  const rawFraction = decimals === 0 ? "" : padded.slice(-decimals);
  let fraction = rawFraction;
  while (fraction.length > 2 && fraction.endsWith("0")) {
    fraction = fraction.slice(0, -1);
  }
  if (fraction.length < 2) {
    fraction = fraction.padEnd(2, "0");
  }
  return `${BigInt(whole).toString()}.${fraction}`;
}

export function actionFromX402(input: X402BindingInput): InntrisActionV1 {
  const requirements = normalisePaymentRequirements(input.paymentRequirements);
  const payload =
    input.paymentPayload === undefined ? undefined : normalisePaymentPayload(input.paymentPayload);

  if (
    payload !== undefined &&
    paymentRequirementsHash(payload.accepted) !== paymentRequirementsHash(requirements)
  ) {
    throw new X402BindingError(
      "The payment payload is bound to different x402 payment requirements",
    );
  }

  return InntrisActionV1Schema.parse({
    version: "inntris-action-v1",
    principal_id: input.principalId,
    agent_id: input.agentId,
    action_type: "financial_transaction",
    rail: "x402",
    transaction: {
      amount: formatAtomicAmount(requirements.amount, input.assetDecimals),
      asset: requirements.asset,
      network: requirements.network,
      payee: requirements.payTo,
      purpose: input.purpose,
    },
    protocol_reference: {
      type: "x402",
      resource: input.resource,
      scheme: requirements.scheme,
      payment_requirements_hash: paymentRequirementsHash(requirements),
      payment_payload_hash: payload === undefined ? null : paymentPayloadHash(payload),
    },
  });
}
