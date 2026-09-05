import { z } from "zod";

import {
  AP2_COMMIT,
  PULSE_BUNDLE_VERSION,
  PULSE_CASE_COUNT,
  PULSE_CASE_VERSION,
  X402_COMMIT,
  X402_PACKAGE_VERSION,
} from "./constants.js";
import type { ConformanceBundle, ConformanceCase, ConformanceCaseEnvelope } from "./types.js";

const NonEmptyString = z.string().min(1).max(2_048);
const Identifier = z.string().min(1).max(512);
const MAX_UINT256 = (1n << 256n) - 1n;

function isCanonicalBase64Url32(value: string): boolean {
  return Buffer.from(value, "base64url").toString("base64url") === value;
}

function isUint256(value: string): boolean {
  try {
    return BigInt(value) <= MAX_UINT256;
  } catch {
    return false;
  }
}

const Base64Url32 = z
  .string()
  .regex(/^[A-Za-z0-9_-]{43}$/u)
  .refine(isCanonicalBase64Url32, "Expected canonical unpadded base64url for 32 bytes");
const UnsignedAtomic = z
  .string()
  .regex(/^(0|[1-9]\d*)$/u)
  .refine(isUint256, "Expected an unsigned 256 bit integer");
const EvmAddress = z.string().regex(/^0x[0-9a-fA-F]{40}$/u);
const Hex32 = z.string().regex(/^0x[0-9a-fA-F]{64}$/u);
const HexSignature = z.string().regex(/^0x[0-9a-fA-F]{130}$/u);
const Epoch = z.number().int().nonnegative();
const Caip2Network = z
  .string()
  .regex(/^eip155:(0|[1-9]\d*)$/u)
  .refine((network) => isUint256(network.slice("eip155:".length)), "Invalid EIP-155 chain id");

export const SourcePinsSchema = z
  .object({
    ap2Commit: z.literal(AP2_COMMIT),
    x402Commit: z.literal(X402_COMMIT),
    x402PackageVersion: z.literal(X402_PACKAGE_VERSION),
  })
  .strict();

const MerchantSchema = z
  .object({
    id: z.string().max(512),
    name: NonEmptyString,
    website: z.url().max(2_048),
  })
  .strict();

const AmountSchema = z
  .object({
    amount: z.number().int().nonnegative(),
    currency: z.string().regex(/^[A-Z]{3}$/u),
  })
  .strict();

const Eip712DomainSchema = z
  .object({
    name: NonEmptyString,
    version: NonEmptyString,
  })
  .strict();

const Ap2X402ExtensionSchema = z
  .object({
    version: z.number().int().nonnegative(),
    scheme: NonEmptyString,
    network: Caip2Network,
    asset: EvmAddress,
    amount: UnsignedAtomic,
    payTo: EvmAddress,
    payer: EvmAddress,
    ap2PayeeId: z.string().max(512),
    ap2PaymentAmount: AmountSchema,
    maxTimeoutSeconds: z.number().int().positive(),
    eip712Domain: Eip712DomainSchema,
    nonceBinding: NonEmptyString,
  })
  .strict();

const PaymentInstrumentSchema = z
  .object({
    id: Identifier,
    type: NonEmptyString,
    description: NonEmptyString,
    x402: Ap2X402ExtensionSchema.optional(),
  })
  .strict();

const ProfilePaymentInstrumentSchema = z
  .object({
    id: Identifier,
    type: NonEmptyString,
    description: NonEmptyString,
    x402: Ap2X402ExtensionSchema,
  })
  .strict();

const PaymentReferenceConstraintSchema = z
  .object({
    type: z.literal("payment.reference"),
    conditional_transaction_id: Base64Url32,
  })
  .strict();

const AllowedInstrumentsConstraintSchema = z
  .object({
    type: z.literal("payment.allowed_payment_instruments"),
    allowed: z.array(PaymentInstrumentSchema).min(1).max(128),
  })
  .strict();

const AmountRangeConstraintSchema = z
  .object({
    type: z.literal("payment.amount_range"),
    currency: z.string().regex(/^[A-Z]{3}$/u),
    max: z.number().int().nonnegative(),
    min: z.number().int().nonnegative(),
  })
  .strict();

const AllowedPayeesConstraintSchema = z
  .object({
    type: z.literal("payment.allowed_payees"),
    allowed: z.array(MerchantSchema).min(1).max(128),
  })
  .strict();

const UnsupportedConstraintSchema = z
  .object({ type: NonEmptyString })
  .catchall(z.unknown())
  .refine(
    (constraint) =>
      ![
        "payment.reference",
        "payment.allowed_payment_instruments",
        "payment.amount_range",
        "payment.allowed_payees",
      ].includes(constraint.type),
    "Known constraint has an invalid shape",
  );

const PaymentConstraintSchema = z.union([
  PaymentReferenceConstraintSchema,
  AllowedInstrumentsConstraintSchema,
  AmountRangeConstraintSchema,
  AllowedPayeesConstraintSchema,
  UnsupportedConstraintSchema,
]);

const PublicJwkSchema = z
  .object({
    kty: z.literal("EC"),
    crv: z.literal("P-256"),
    alg: z.literal("ES256"),
    kid: Identifier,
    x: Base64Url32,
    y: Base64Url32,
  })
  .strict();

export const ClosedMandateSchema = z
  .object({
    vct: z.literal("mandate.payment.1"),
    transaction_id: Base64Url32,
    payee: MerchantSchema,
    payment_amount: AmountSchema,
    payment_instrument: ProfilePaymentInstrumentSchema,
    execution_date: z.iso.datetime({ offset: true }),
    iat: Epoch,
    exp: Epoch,
  })
  .strict();

export const OpenMandateSchema = z
  .object({
    vct: z.literal("mandate.payment.open.1"),
    constraints: z.array(PaymentConstraintSchema).min(1).max(128),
    cnf: z.object({ jwk: PublicJwkSchema }).strict(),
    payee: MerchantSchema.optional(),
    payment_amount: AmountSchema.optional(),
    payment_instrument: ProfilePaymentInstrumentSchema.optional(),
    execution_date: z.iso.datetime({ offset: true }).optional(),
    iat: Epoch,
    exp: Epoch,
  })
  .strict();

export const PaymentReceiptSchema = z
  .object({
    status: z.enum(["Success", "Error"]),
    iss: NonEmptyString,
    iat: Epoch,
    reference: Base64Url32,
    error: z.string().nullable(),
    error_description: z.string().nullable(),
    payment_id: Identifier,
    psp_confirmation_id: Identifier.nullable().optional(),
    network_confirmation_id: Hex32.nullable().optional(),
  })
  .strict();

const CryptographicEvidenceSchema = z
  .object({
    mandateChain: z.string().min(16).max(1_000_000),
    paymentReceiptJwt: z.string().min(16).max(1_000_000),
    trustedRootPublicJwk: PublicJwkSchema,
    trustedReceiptPublicJwk: PublicJwkSchema,
    expectedAudience: NonEmptyString,
    expectedNonce: NonEmptyString,
  })
  .strict();

const VerificationSchema = z
  .object({
    verifier: NonEmptyString,
    verifiedAtEpochSeconds: Epoch,
    clockSkewSeconds: z.number().int().nonnegative().max(300),
    openCheckoutReference: Base64Url32,
    closedMandateClaimsHash: Base64Url32,
    openMandateClaimsHash: Base64Url32,
    closedMandateReference: Base64Url32,
    cryptographicEvidence: CryptographicEvidenceSchema,
  })
  .strict();

const Ap2Schema = z
  .object({
    closedMandate: ClosedMandateSchema,
    openMandate: OpenMandateSchema,
    paymentReceipt: PaymentReceiptSchema.optional(),
    verification: VerificationSchema,
  })
  .strict();

const RequirementsExtraSchema = z
  .object({
    name: NonEmptyString,
    version: NonEmptyString,
    assetTransferMethod: NonEmptyString,
    ap2MandateReference: Base64Url32,
    ap2NonceDerivation: NonEmptyString,
  })
  .strict();

const RequirementsSchema = z
  .object({
    scheme: NonEmptyString,
    network: Caip2Network,
    asset: EvmAddress,
    amount: UnsignedAtomic,
    payTo: EvmAddress,
    maxTimeoutSeconds: z.number().int().positive(),
    extra: RequirementsExtraSchema,
  })
  .strict();

const ResourceSchema = z
  .object({
    url: z.url().max(2_048),
    description: NonEmptyString,
    mimeType: NonEmptyString,
  })
  .strict();

const AuthorizationSchema = z
  .object({
    from: EvmAddress,
    to: EvmAddress,
    value: UnsignedAtomic,
    validAfter: UnsignedAtomic,
    validBefore: UnsignedAtomic,
    nonce: Hex32,
  })
  .strict();

const X402PayloadSchema = z
  .object({
    x402Version: z.number().int().nonnegative(),
    resource: ResourceSchema,
    accepted: RequirementsSchema,
    payload: z
      .object({
        signature: HexSignature,
        authorization: AuthorizationSchema,
      })
      .strict(),
    extensions: z.unknown().optional(),
  })
  .strict();

const SettlementSchema = z
  .object({
    success: z.boolean(),
    payer: EvmAddress,
    transaction: z
      .string()
      .regex(/^0x[0-9a-fA-F]+$/u)
      .max(130),
    network: Caip2Network,
    amount: UnsignedAtomic.optional(),
    errorReason: NonEmptyString.optional(),
  })
  .strict();

const X402Schema = z
  .object({
    requirements: RequirementsSchema,
    payload: X402PayloadSchema,
    settlement: SettlementSchema,
  })
  .strict();

export const ConformanceCaseSchema = z
  .object({
    caseVersion: z.literal(PULSE_CASE_VERSION),
    sourcePins: SourcePinsSchema,
    id: Identifier,
    description: NonEmptyString,
    nowEpochSeconds: Epoch,
    ap2: Ap2Schema,
    x402: X402Schema,
    inputHash: Base64Url32,
  })
  .strict();

const ConformanceCaseEnvelopeSchema = z
  .object({
    caseVersion: z.literal(PULSE_CASE_VERSION),
    sourcePins: SourcePinsSchema,
    id: Identifier,
    description: NonEmptyString,
    nowEpochSeconds: Epoch,
    ap2: z.record(z.string(), z.unknown()),
    x402: z.record(z.string(), z.unknown()),
    inputHash: Base64Url32,
  })
  .strict();

export const ConformanceBundleSchema = z
  .object({
    bundleVersion: z.literal(PULSE_BUNDLE_VERSION),
    sourcePins: SourcePinsSchema,
    generatedAt: z.iso.datetime({ offset: true }),
    cases: z.array(ConformanceCaseEnvelopeSchema).length(PULSE_CASE_COUNT),
  })
  .strict();

export function parseConformanceBundle(value: unknown): ConformanceBundle {
  const bundle = ConformanceBundleSchema.parse(value) as ConformanceBundle;
  const ids = new Set<string>();
  for (const fixtureCase of bundle.cases) {
    if (ids.has(fixtureCase.id)) throw new TypeError(`Duplicate case id: ${fixtureCase.id}`);
    ids.add(fixtureCase.id);
  }
  return bundle;
}

export function parseConformanceCase(value: unknown): ConformanceCase {
  return ConformanceCaseSchema.parse(value);
}

export function tryParseConformanceCase(
  value: ConformanceCaseEnvelope,
): ConformanceCase | undefined {
  const result = ConformanceCaseSchema.safeParse(value);
  return result.success ? result.data : undefined;
}
