import { randomUUID } from "node:crypto";

import {
  KeyRegistrySchema,
  canonicalBytes,
  hashCanonical,
  publicKeyFingerprint,
  type InntrisDecisionV1,
  type KeyRegistry,
  type SigningProvider,
} from "@inntris/decision-core";
import nacl from "tweetnacl";

import {
  A2AActionReceiptSchema,
  type A2AActionReceipt,
  type A2ASettlementObservation,
  type A2ATaskReference,
} from "./types.js";

type SignableReceipt = Omit<A2AActionReceipt, "signing"> & {
  signing: Omit<A2AActionReceipt["signing"], "signature">;
};

type ReceiptFingerprintPayload = Omit<SignableReceipt, "receipt_fingerprint">;

export interface CreateA2AActionReceiptInput {
  task: A2ATaskReference;
  resource: string;
  paymentSubmissionId: string;
  decision: InntrisDecisionV1;
  settlement: A2ASettlementObservation;
  executionRef: string;
  delegateResult: unknown;
  signer: SigningProvider;
  executedAt: Date;
  receiptId?: string;
}

export interface A2AReceiptVerificationResult {
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

export function calculateA2AReceiptFingerprint(receipt: SignableReceipt): string {
  return hashCanonical(fingerprintPayload(receipt));
}

export async function createA2AActionReceipt(
  input: CreateA2AActionReceiptInput,
): Promise<A2AActionReceipt> {
  const unsigned = {
    version: "inntris-a2a-action-receipt-v1" as const,
    receipt_id: input.receiptId ?? randomUUID(),
    task_id: input.task.id,
    context_id: input.task.contextId,
    resource: input.resource,
    payment_submission_id: input.paymentSubmissionId,
    decision_id: input.decision.decision_id,
    decision_fingerprint: input.decision.decision_fingerprint,
    action_hash: input.decision.action_hash,
    settlement_ref: input.settlement.settlement_ref ?? "",
    settlement_evidence_hash: hashCanonical(input.settlement),
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
    receipt_fingerprint: calculateA2AReceiptFingerprint({
      ...unsigned,
      receipt_fingerprint:
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    }),
  };
  const signature = await input.signer.sign(canonicalBytes(signable));
  return A2AActionReceiptSchema.parse({
    ...signable,
    signing: {
      ...signable.signing,
      signature,
    },
  });
}

export function verifyA2AActionReceipt(
  receiptInput: unknown,
  registryInput: unknown,
): A2AReceiptVerificationResult {
  const checks = {
    schema: false,
    fingerprint: false,
    key: false,
    signature: false,
  };
  const parsedReceipt = A2AActionReceiptSchema.safeParse(receiptInput);
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
  checks.fingerprint = calculateA2AReceiptFingerprint(signable) === receipt.receipt_fingerprint;

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
