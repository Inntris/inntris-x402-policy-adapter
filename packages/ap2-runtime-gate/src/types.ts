import {
  Base64UrlSchema,
  HashSchema,
  IdentifierSchema,
  IsoTimestampSchema,
  type InntrisActionV1,
  type InntrisDecisionV1,
} from "@inntris/decision-core";
import { z } from "zod";

export const AP2_OFFICIAL_REPOSITORY = "https://github.com/google-agentic-commerce/AP2";
export const AP2_OFFICIAL_SDK_COMMIT = "e1ea56db72a6385bce3e5c1112b3a56ce60acb43";
export const AP2_PROTOCOL_VERSION = "0.2";

const CompactTokenSchema = z.string().min(16).max(1_000_000);
const PublicJwkSchema = z.record(z.string(), z.unknown());
const UnsignedIntegerSchema = z.string().regex(/^(0|[1-9]\d*)$/u);
const CurrencySchema = z.string().regex(/^[A-Z]{3}$/u);

export const AP2MandatePresentationSchema = z
  .object({
    version: z.literal("inntris-ap2-mandate-presentation-v1"),
    checkout_mandate_token: CompactTokenSchema,
    payment_mandate_token: CompactTokenSchema,
    checkout_jwt: CompactTokenSchema,
    checkout_audience: IdentifierSchema,
    checkout_nonce: IdentifierSchema,
    checkout_issuer: IdentifierSchema,
    payment_audience: IdentifierSchema,
    payment_nonce: IdentifierSchema,
  })
  .strict();

export const AP2OfficialVerificationRequestSchema = AP2MandatePresentationSchema.extend({
  issuer_public_jwk: PublicJwkSchema,
  merchant_public_jwk: PublicJwkSchema,
  expected_merchant_id: IdentifierSchema,
  current_time_epoch: z.number().int().nonnegative(),
}).strict();

const VerifiedMandateSchema = z
  .object({
    verified: z.literal(true),
    mandate_hash: HashSchema,
    expires_at: IsoTimestampSchema,
  })
  .strict();

export const AP2OfficialVerificationSchema = z
  .object({
    version: z.literal("inntris-ap2-official-verification-v1"),
    sdk: z
      .object({
        repository: z.literal(AP2_OFFICIAL_REPOSITORY),
        commit: z.literal(AP2_OFFICIAL_SDK_COMMIT),
        protocol_version: z.literal(AP2_PROTOCOL_VERSION),
      })
      .strict(),
    mode: z.literal("autonomous"),
    intent: z
      .object({
        verified: z.boolean(),
        checkout_open_mandate_hash: HashSchema,
        payment_open_mandate_hash: HashSchema,
      })
      .strict(),
    checkout: VerifiedMandateSchema.extend({
      checkout_hash: Base64UrlSchema,
      checkout_id: IdentifierSchema,
      merchant_id: IdentifierSchema,
      merchant_name: z.string().min(1).max(512),
    }).strict(),
    payment: VerifiedMandateSchema.extend({
      transaction_id: Base64UrlSchema,
      payee_id: IdentifierSchema,
      payee_name: z.string().min(1).max(512),
      amount_minor: UnsignedIntegerSchema,
      currency: CurrencySchema,
      payment_instrument_type: z.string().min(1).max(128),
    }).strict(),
    verified_at: IsoTimestampSchema,
  })
  .strict();

export const AP2ActionReceiptSchema = z
  .object({
    version: z.literal("inntris-ap2-action-receipt-v1"),
    receipt_id: IdentifierSchema,
    receipt_fingerprint: HashSchema,
    intent_verification_hash: HashSchema,
    checkout_mandate_hash: HashSchema,
    payment_mandate_hash: HashSchema,
    checkout_hash: Base64UrlSchema,
    transaction_id: Base64UrlSchema,
    decision_id: IdentifierSchema,
    decision_fingerprint: HashSchema,
    action_hash: HashSchema,
    execution_ref: z.string().min(1).max(512),
    delegate_result_hash: HashSchema,
    executed_at: IsoTimestampSchema,
    signing: z
      .object({
        alg: z.literal("Ed25519"),
        key_id: IdentifierSchema,
        signature: Base64UrlSchema,
      })
      .strict(),
  })
  .strict();

export type AP2MandatePresentation = z.infer<typeof AP2MandatePresentationSchema>;
export type AP2OfficialVerificationRequest = z.infer<typeof AP2OfficialVerificationRequestSchema>;
export type AP2OfficialVerification = z.infer<typeof AP2OfficialVerificationSchema>;
export type AP2ActionReceipt = z.infer<typeof AP2ActionReceiptSchema>;

export interface AP2TrustMaterial {
  issuerPublicJwk: Record<string, unknown>;
  merchantPublicJwk: Record<string, unknown>;
}

export interface AP2TrustProvider {
  resolve(expectedMerchantId: string): Promise<AP2TrustMaterial>;
}

export interface AP2OfficialVerifier {
  verify(input: AP2OfficialVerificationRequest): Promise<unknown>;
}

export interface AP2RuntimeGateInput {
  mandates: AP2MandatePresentation;
  principalId: string;
  agentId: string;
  resource: string;
  purpose: string;
  expectedMerchantId: string;
  expectedAmountMinor: string;
  expectedCurrency: string;
  extensions?: Record<string, unknown> | undefined;
}

export interface AP2DelegateInput {
  action: InntrisActionV1;
  decision: InntrisDecisionV1;
  verification: AP2OfficialVerification;
  executionRef: string;
}

export type AP2Delegate<T> = (input: AP2DelegateInput) => Promise<T>;

export interface AP2RuntimeGateResult<T> {
  action: InntrisActionV1;
  decision: InntrisDecisionV1;
  verification: AP2OfficialVerification;
  execution_ref: string;
  receipt: AP2ActionReceipt;
  result: T;
  replayed: boolean;
}

export type AP2GateReasonCode =
  | "INVALID_AP2_INPUT"
  | "AP2_TRUST_UNAVAILABLE"
  | "AP2_VERIFICATION_FAILED"
  | "AP2_SDK_PROVENANCE_MISMATCH"
  | "AP2_VERIFICATION_STALE"
  | "AP2_MANDATE_EXPIRED"
  | "AP2_INTENT_INVALID"
  | "AP2_CHECKOUT_BINDING_MISMATCH"
  | "AP2_PAYMENT_BINDING_MISMATCH"
  | "DECISION_INVALID"
  | "DECISION_NOT_ALLOW"
  | "DECISION_CONSUMPTION_FAILED"
  | "AP2_EXECUTION_CONFLICT"
  | "AP2_EXECUTION_IN_PROGRESS"
  | "AP2_EXECUTION_STORE_UNAVAILABLE"
  | "AP2_DELEGATE_FAILED"
  | "AP2_RECEIPT_SIGNING_FAILED";
