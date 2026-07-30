import { randomUUID } from "node:crypto";

import {
  KeyRegistrySchema,
  canonicalBytes,
  hashCanonical,
  publicKeyFingerprint,
  type InntrisActionV1,
  type InntrisDecisionV1,
  type KeyRegistry,
  type SigningProvider,
} from "@inntris/decision-core";
import nacl from "tweetnacl";

import {
  AP2ActionReceiptSchema,
  type AP2ActionReceipt,
  type AP2OfficialVerification,
} from "./types.js";

type SignableReceipt = Omit<AP2ActionReceipt, "signing"> & {
  signing: Omit<AP2ActionReceipt["signing"], "signature">;
};

type ReceiptFingerprintPayload = Omit<SignableReceipt, "receipt_fingerprint">;

export interface CreateAP2ActionReceiptInput {
  action: InntrisActionV1;
  decision: InntrisDecisionV1;
  verification: AP2OfficialVerification;
  executionRef: string;
  delegateResult: unknown;
  signer: SigningProvider;
  executedAt: Date;
  receiptId?: string;
}

export interface AP2ReceiptVerificationResult {
  valid: boolean;
  checks: {
    schema: boolean;
    fingerprint: boolean;
    key: boolean;
    signature: boolean;
  };
}

function fingerprintPayload(receipt: SignableReceipt): ReceiptFingerprintPayload {
  const { receipt_fingerprint: ignored, ...payload } = receipt;
  void ignored;
  return payload;
}

export function calculateAP2ReceiptFingerprint(receipt: SignableReceipt): string {
  return hashCanonical(fingerprintPayload(receipt));
}

export async function createAP2ActionReceipt(
  input: CreateAP2ActionReceiptInput,
): Promise<AP2ActionReceipt> {
  if (input.action.protocol_reference.type !== "ap2") {
    throw new TypeError("AP2 receipt requires an AP2 action");
  }
  const unsigned = {
    version: "inntris-ap2-action-receipt-v1" as const,
    receipt_id: input.receiptId ?? randomUUID(),
    intent_verification_hash: input.action.protocol_reference.intent_verification_hash,
    checkout_mandate_hash: input.verification.checkout.mandate_hash,
    payment_mandate_hash: input.verification.payment.mandate_hash,
    checkout_hash: input.verification.checkout.checkout_hash,
    transaction_id: input.verification.payment.transaction_id,
    decision_id: input.decision.decision_id,
    decision_fingerprint: input.decision.decision_fingerprint,
    action_hash: input.decision.action_hash,
    execution_ref: input.executionRef,
    delegate_result_hash: hashCanonical(input.delegateResult ?? null),
    executed_at: input.executedAt.toISOString(),
    signing: {
      alg: input.signer.algorithm,
      key_id: input.signer.keyId,
    },
  };
  const signable: SignableReceipt = {
    ...unsigned,
    receipt_fingerprint: calculateAP2ReceiptFingerprint({
      ...unsigned,
      receipt_fingerprint:
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    }),
  };
  const signature = await input.signer.sign(canonicalBytes(signable));
  return AP2ActionReceiptSchema.parse({
    ...signable,
    signing: {
      ...signable.signing,
      signature,
    },
  });
}

export function verifyAP2ActionReceipt(
  receiptInput: unknown,
  registryInput: unknown,
): AP2ReceiptVerificationResult {
  const checks = {
    schema: false,
    fingerprint: false,
    key: false,
    signature: false,
  };
  const parsedReceipt = AP2ActionReceiptSchema.safeParse(receiptInput);
  const parsedRegistry = KeyRegistrySchema.safeParse(registryInput);
  if (!parsedReceipt.success || !parsedRegistry.success) {
    return { valid: false, checks };
  }
  checks.schema = true;
  const receipt = parsedReceipt.data;
  const signable: SignableReceipt = {
    ...receipt,
    signing: {
      alg: receipt.signing.alg,
      key_id: receipt.signing.key_id,
    },
  };
  checks.fingerprint = calculateAP2ReceiptFingerprint(signable) === receipt.receipt_fingerprint;

  const registry: KeyRegistry = parsedRegistry.data;
  const key = registry.keys.find((entry) => entry.key_id === receipt.signing.key_id);
  const executedAt = Date.parse(receipt.executed_at);
  if (
    key === undefined ||
    key.status === "revoked" ||
    key.alg !== receipt.signing.alg ||
    executedAt < Date.parse(key.not_before) ||
    (key.not_after !== null && executedAt >= Date.parse(key.not_after))
  ) {
    return { valid: false, checks };
  }
  const publicKey = Buffer.from(key.public_key, "base64url");
  checks.key =
    publicKey.byteLength === nacl.sign.publicKeyLength &&
    publicKeyFingerprint(publicKey) === key.fingerprint;
  if (!checks.key) {
    return { valid: false, checks };
  }
  try {
    const signature = Buffer.from(receipt.signing.signature, "base64url");
    checks.signature =
      signature.byteLength === nacl.sign.signatureLength &&
      nacl.sign.detached.verify(canonicalBytes(signable), signature, publicKey);
  } catch {
    checks.signature = false;
  }
  return {
    valid: Object.values(checks).every(Boolean),
    checks,
  };
}
