import { InntrisActionV1Schema, hashCanonical, type InntrisActionV1 } from "@inntris/decision-core";

import {
  AP2_PROTOCOL_VERSION,
  AP2MandatePresentationSchema,
  AP2OfficialVerificationSchema,
  type AP2OfficialVerification,
  type AP2RuntimeGateInput,
} from "./types.js";

export class AP2BindingError extends Error {
  override readonly name = "AP2BindingError";
}

export function formatMinorUnitAmount(amount: string, decimals: number): string {
  if (!/^(0|[1-9]\d*)$/u.test(amount)) {
    throw new AP2BindingError("AP2 amount must be an unsigned minor-unit integer string");
  }
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 18) {
    throw new AP2BindingError("currencyDecimals must be an integer from 0 to 18");
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

export function intentVerificationHash(verification: AP2OfficialVerification): string {
  return hashCanonical({
    version: "inntris-ap2-intent-verification-v1",
    checkout_open_mandate_hash: verification.intent.checkout_open_mandate_hash,
    payment_open_mandate_hash: verification.intent.payment_open_mandate_hash,
    checkout_mandate_hash: verification.checkout.mandate_hash,
    payment_mandate_hash: verification.payment.mandate_hash,
  });
}

export function actionFromAP2(
  input: AP2RuntimeGateInput,
  verificationInput: unknown,
  currencyDecimals: number,
): InntrisActionV1 {
  AP2MandatePresentationSchema.parse(input.mandates);
  const verification = AP2OfficialVerificationSchema.parse(verificationInput);
  const intentHash = intentVerificationHash(verification);
  return InntrisActionV1Schema.parse({
    version: "inntris-action-v1",
    principal_id: input.principalId,
    agent_id: input.agentId,
    action_type: "financial_transaction",
    rail: "ap2",
    transaction: {
      amount: formatMinorUnitAmount(verification.payment.amount_minor, currencyDecimals),
      asset: verification.payment.currency,
      network: verification.payment.payment_instrument_type,
      payee: verification.payment.payee_id,
      purpose: input.purpose,
    },
    protocol_reference: {
      type: "ap2",
      protocol_version: AP2_PROTOCOL_VERSION,
      resource: input.resource,
      mode: "autonomous",
      intent_verification_hash: intentHash,
      checkout_mandate_hash: verification.checkout.mandate_hash,
      payment_mandate_hash: verification.payment.mandate_hash,
      checkout_hash: verification.checkout.checkout_hash,
      transaction_id: verification.payment.transaction_id,
    },
    extensions: {
      ...input.extensions,
      inntris_ap2: {
        sdk_commit: verification.sdk.commit,
        checkout_id: verification.checkout.checkout_id,
        payment_instrument_type: verification.payment.payment_instrument_type,
      },
    },
  });
}
