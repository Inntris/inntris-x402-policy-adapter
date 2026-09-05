import {
  EIP3009_SAFETY_BUFFER_SECONDS,
  EXPECTED_AP2_VERIFIER,
  REQUIRED_NONCE_DERIVATION,
  REQUIRED_TRANSFER_METHOD,
} from "./constants.js";
import { verifyEip3009Signature } from "./eip3009.js";
import { FailureCollector } from "./failures.js";
import { calculateInputHash, canonicalHash, sha256Base64Url } from "./hashing.js";
import {
  ClosedMandateSchema,
  OpenMandateSchema,
  PaymentReceiptSchema,
  tryParseConformanceCase,
} from "./schemas.js";
import type {
  Ap2X402Extension,
  ClosedMandate,
  ConformanceBundle,
  ConformanceCase,
  ConformanceCaseEnvelope,
  ConformanceResult,
  OpenMandate,
  PaymentReceipt,
  PaymentConstraint,
  PaymentInstrument,
  StructuredAp2Verifier,
} from "./types.js";
import { addressesEqual, canonicalEqual, isHex32 } from "./values.js";

const SUPPORTED_CONSTRAINTS = new Set([
  "payment.reference",
  "payment.allowed_payment_instruments",
  "payment.amount_range",
  "payment.allowed_payees",
]);

function constraintType(constraint: PaymentConstraint): string | undefined {
  const type = Reflect.get(constraint, "type");
  return typeof type === "string" ? type : undefined;
}

function instrumentsMatch(allowed: PaymentInstrument, selected: PaymentInstrument): boolean {
  return (
    allowed.id === selected.id &&
    allowed.type === selected.type &&
    allowed.x402 !== undefined &&
    selected.x402 !== undefined &&
    canonicalEqual(allowed.x402, selected.x402)
  );
}

function evaluateConstraints(
  open: OpenMandate,
  closed: ClosedMandate,
  openCheckoutReference: string,
  failures: FailureCollector,
): void {
  const seen = new Set<string>();
  for (const constraint of open.constraints) {
    const type = constraintType(constraint);
    if (type === undefined || !SUPPORTED_CONSTRAINTS.has(type)) {
      failures.add("AP2_UNSUPPORTED_CONSTRAINT");
      continue;
    }
    seen.add(type);
    if (type === "payment.reference") {
      const reference =
        "conditional_transaction_id" in constraint
          ? constraint.conditional_transaction_id
          : undefined;
      const mismatch = reference !== openCheckoutReference;
      failures.add("AP2_PAYMENT_REFERENCE_MISMATCH", mismatch);
      continue;
    }
    if (type === "payment.allowed_payment_instruments") {
      const rawAllowed: unknown = "allowed" in constraint ? constraint.allowed : undefined;
      const allowed: unknown[] = Array.isArray(rawAllowed) ? rawAllowed : [];
      const mismatch = !allowed.some(
        (instrument) =>
          typeof instrument === "object" &&
          instrument !== null &&
          "id" in instrument &&
          "type" in instrument &&
          "x402" in instrument &&
          instrumentsMatch(instrument as PaymentInstrument, closed.payment_instrument),
      );
      failures.add("AP2_PAYMENT_INSTRUMENT_NOT_ALLOWED", mismatch);
      failures.add("AP2_CONSTRAINT_VIOLATION", mismatch);
      continue;
    }
    if (type === "payment.amount_range") {
      const currency: unknown = "currency" in constraint ? constraint.currency : undefined;
      const minimum: unknown = "min" in constraint ? constraint.min : undefined;
      const maximum: unknown = "max" in constraint ? constraint.max : undefined;
      const mismatch =
        currency !== closed.payment_amount.currency ||
        typeof minimum !== "number" ||
        typeof maximum !== "number" ||
        closed.payment_amount.amount < minimum ||
        closed.payment_amount.amount > maximum;
      failures.add("AP2_CONSTRAINT_VIOLATION", mismatch);
      continue;
    }
    const rawAllowed: unknown = "allowed" in constraint ? constraint.allowed : undefined;
    const allowed: unknown[] = Array.isArray(rawAllowed) ? rawAllowed : [];
    const mismatch =
      closed.payee.id.length === 0 ||
      !allowed.some(
        (merchant) =>
          typeof merchant === "object" &&
          merchant !== null &&
          "id" in merchant &&
          typeof merchant.id === "string" &&
          merchant.id.length > 0 &&
          merchant.id === closed.payee.id,
      );
    failures.add("AP2_CONSTRAINT_VIOLATION", mismatch);
  }
  for (const required of SUPPORTED_CONSTRAINTS) {
    failures.add("AP2_CONSTRAINT_VIOLATION", !seen.has(required));
  }
}

function evaluatePresets(
  open: OpenMandate,
  closed: ClosedMandate,
  failures: FailureCollector,
): void {
  let mismatch = false;
  if (open.payee !== undefined) {
    mismatch ||=
      open.payee.id.length === 0 ||
      closed.payee.id.length === 0 ||
      open.payee.id !== closed.payee.id;
  }
  if (open.payment_amount !== undefined) {
    mismatch ||= !canonicalEqual(open.payment_amount, closed.payment_amount);
  }
  if (open.payment_instrument !== undefined) {
    mismatch ||= !canonicalEqual(open.payment_instrument, closed.payment_instrument);
  }
  if (open.execution_date !== undefined) {
    mismatch ||= open.execution_date !== closed.execution_date;
  }
  failures.add("AP2_OPEN_PRESET_MISMATCH", mismatch);
}

function evaluateAp2X402(
  extension: Ap2X402Extension,
  fixtureCase: ConformanceCase,
  closed: ClosedMandate,
  failures: FailureCollector,
): void {
  const { requirements } = fixtureCase.x402;
  const payeeIdentityMismatch =
    extension.ap2PayeeId.length === 0 || extension.ap2PayeeId !== closed.payee.id;

  failures.add(
    "X402_UNSUPPORTED_EXTENSION",
    extension.version !== 2 || extension.nonceBinding !== REQUIRED_NONCE_DERIVATION,
  );
  failures.add(
    "AP2_X402_SCHEME_MISMATCH",
    extension.scheme !== "exact" ||
      requirements.scheme !== "exact" ||
      extension.scheme !== requirements.scheme,
  );
  failures.add("AP2_X402_NETWORK_MISMATCH", extension.network !== requirements.network);
  failures.add("AP2_X402_ASSET_MISMATCH", !addressesEqual(extension.asset, requirements.asset));
  failures.add("AP2_X402_AMOUNT_MISMATCH", extension.amount !== requirements.amount);
  failures.add(
    "AP2_X402_PAYEE_MISMATCH",
    !addressesEqual(extension.payTo, requirements.payTo) || payeeIdentityMismatch,
  );
  failures.add(
    "AP2_X402_COMMERCE_BINDING_MISMATCH",
    payeeIdentityMismatch || !canonicalEqual(extension.ap2PaymentAmount, closed.payment_amount),
  );
  failures.add(
    "AP2_X402_TIMEOUT_MISMATCH",
    extension.maxTimeoutSeconds !== requirements.maxTimeoutSeconds,
  );
  failures.add(
    "AP2_X402_EIP712_DOMAIN_MISMATCH",
    extension.eip712Domain.name !== requirements.extra.name ||
      extension.eip712Domain.version !== requirements.extra.version,
  );
}

function parseVerifiedClaims<T>(
  value: Record<string, unknown> | undefined,
  parser: { safeParse(input: unknown): { success: true; data: T } | { success: false } },
): T | undefined {
  const result = parser.safeParse(value);
  return result.success ? result.data : undefined;
}

export async function evaluateCase(
  caseInput: ConformanceCaseEnvelope,
  ap2Verifier: StructuredAp2Verifier,
): Promise<ConformanceResult> {
  const parsedCase = tryParseConformanceCase(caseInput);
  if (parsedCase === undefined) {
    return {
      id: caseInput.id,
      decision: "reject",
      failureCodes: ["INPUT_SCHEMA_INVALID"],
    };
  }
  const fixtureCase = parsedCase;
  const failures = new FailureCollector();
  failures.add("INPUT_HASH_MISMATCH", calculateInputHash(fixtureCase) !== fixtureCase.inputHash);

  const verification = fixtureCase.ap2.verification;
  failures.add(
    "AP2_VERIFICATION_CONTEXT_MISMATCH",
    verification.verifier !== EXPECTED_AP2_VERIFIER ||
      verification.verifiedAtEpochSeconds !== fixtureCase.nowEpochSeconds ||
      verification.clockSkewSeconds !== 0,
  );

  let structured;
  try {
    structured = await ap2Verifier.verify({
      ...verification.cryptographicEvidence,
      currentTimeEpoch: fixtureCase.nowEpochSeconds,
      clockSkewSeconds: verification.clockSkewSeconds,
    });
  } catch {
    structured = undefined;
  }

  failures.add("AP2_CRYPTOGRAPHIC_EVIDENCE_INVALID", structured === undefined);

  const verifiedOpen =
    structured?.openMandate.status === "verified"
      ? parseVerifiedClaims(structured.openMandate.claims, OpenMandateSchema)
      : undefined;
  const verifiedClosed =
    structured?.closedMandate.status === "verified"
      ? parseVerifiedClaims(structured.closedMandate.claims, ClosedMandateSchema)
      : undefined;
  const verifiedReceipt =
    structured?.receipt.status === "verified"
      ? parseVerifiedClaims(structured.receipt.claims, PaymentReceiptSchema)
      : undefined;
  const openVerified = structured?.openMandate.status === "verified" && verifiedOpen !== undefined;
  const closedVerified =
    structured?.closedMandate.status === "verified" && verifiedClosed !== undefined;
  const keyBindingVerified = structured?.keyBinding.status === "verified";
  const receiptCryptographicallyVerified =
    structured?.receipt.status === "verified" && verifiedReceipt !== undefined;

  failures.add(
    "AP2_OPEN_MANDATE_UNVERIFIED",
    structured?.openMandate.status === "invalid" ||
      (structured?.openMandate.status === "verified" && verifiedOpen === undefined),
  );
  failures.add(
    "AP2_CLOSED_MANDATE_UNVERIFIED",
    structured?.closedMandate.status === "invalid" ||
      (structured?.closedMandate.status === "verified" && verifiedClosed === undefined),
  );
  failures.add("AP2_KEY_BINDING_UNVERIFIED", structured?.keyBinding.status === "invalid");

  const normalisedReceipt = fixtureCase.ap2.paymentReceipt;
  failures.add(
    "AP2_RECEIPT_UNVERIFIED",
    structured?.receipt.status === "invalid" ||
      (structured?.receipt.status === "verified" && verifiedReceipt === undefined) ||
      (receiptCryptographicallyVerified &&
        (normalisedReceipt === undefined || !canonicalEqual(normalisedReceipt, verifiedReceipt))),
  );

  const issuerJwt =
    structured?.closedMandate.status === "verified"
      ? structured.closedMandate.issuerJwt
      : undefined;
  const derivedReference =
    closedVerified && typeof issuerJwt === "string" ? sha256Base64Url(issuerJwt) : undefined;
  failures.add(
    "AP2_CLOSED_MANDATE_REFERENCE_MISMATCH",
    derivedReference !== undefined && derivedReference !== verification.closedMandateReference,
  );

  failures.add(
    "AP2_CLOSED_MANDATE_CLAIMS_HASH_MISMATCH",
    canonicalHash(fixtureCase.ap2.closedMandate) !== verification.closedMandateClaimsHash ||
      (verifiedClosed !== undefined &&
        canonicalHash(verifiedClosed) !== verification.closedMandateClaimsHash),
  );
  failures.add(
    "AP2_OPEN_MANDATE_CLAIMS_HASH_MISMATCH",
    canonicalHash(fixtureCase.ap2.openMandate) !== verification.openMandateClaimsHash ||
      (verifiedOpen !== undefined &&
        canonicalHash(verifiedOpen) !== verification.openMandateClaimsHash),
  );

  const mandatePairs: (readonly [OpenMandate, ClosedMandate])[] = [];
  if (openVerified && closedVerified && keyBindingVerified) {
    mandatePairs.push([fixtureCase.ap2.openMandate, fixtureCase.ap2.closedMandate]);
    mandatePairs.push([verifiedOpen, verifiedClosed]);

    const verifiedReferenceConstraints = verifiedOpen.constraints.filter(
      (constraint) => constraintType(constraint) === "payment.reference",
    );
    const verifiedReferenceMismatch =
      verifiedReferenceConstraints.length === 0 ||
      verifiedReferenceConstraints.some(
        (constraint) =>
          Reflect.get(constraint, "conditional_transaction_id") !==
          verification.openCheckoutReference,
      );
    const verifiedTransactionMismatch =
      verifiedClosed.transaction_id !== verification.openCheckoutReference;
    failures.add(
      "AP2_CHECKOUT_BINDING_UNVERIFIED",
      verifiedReferenceMismatch || verifiedTransactionMismatch,
    );
  }
  for (const [open, closed] of mandatePairs) {
    const referenceConstraints = open.constraints.filter(
      (constraint) => constraintType(constraint) === "payment.reference",
    );
    const referenceMismatch =
      referenceConstraints.length === 0 ||
      referenceConstraints.some(
        (constraint) =>
          Reflect.get(constraint, "conditional_transaction_id") !==
          verification.openCheckoutReference,
      );
    const transactionMismatch = closed.transaction_id !== verification.openCheckoutReference;
    failures.add("AP2_PAYMENT_REFERENCE_MISMATCH", referenceMismatch);
    failures.add("AP2_CLOSED_TRANSACTION_ID_MISMATCH", transactionMismatch);

    evaluateConstraints(open, closed, verification.openCheckoutReference, failures);
    evaluatePresets(open, closed, failures);
    failures.add(
      "AP2_MANDATE_TIME_INVALID",
      open.iat > fixtureCase.nowEpochSeconds ||
        closed.iat > fixtureCase.nowEpochSeconds ||
        open.exp < fixtureCase.nowEpochSeconds ||
        closed.exp < fixtureCase.nowEpochSeconds,
    );
    failures.add("AP2_PAYMENT_INSTRUMENT_NOT_ALLOWED", closed.payment_instrument.type !== "x402");
    const extension = closed.payment_instrument.x402;
    if (extension !== undefined) evaluateAp2X402(extension, fixtureCase, closed, failures);
  }
  failures.add("AP2_MANDATE_TIME_INVALID", structured?.mandateTime.status === "invalid");

  if (receiptCryptographicallyVerified && verifiedReceipt !== undefined) {
    const receipts: PaymentReceipt[] = [verifiedReceipt];
    if (normalisedReceipt !== undefined) receipts.push(normalisedReceipt);
    for (const receipt of receipts) {
      failures.add("AP2_RECEIPT_NOT_SUCCESSFUL", receipt.status !== "Success");
      failures.add(
        "AP2_RECEIPT_REFERENCE_MISMATCH",
        derivedReference !== undefined && receipt.reference !== derivedReference,
      );
      failures.add(
        "AP2_RECEIPT_TRANSACTION_MISMATCH",
        receipt.status === "Success" &&
          receipt.network_confirmation_id !== fixtureCase.x402.settlement.transaction,
      );
    }
  }

  const { payload, requirements, settlement } = fixtureCase.x402;
  const accepted = payload.accepted;
  failures.add("X402_ACCEPTED_REQUIREMENTS_MISMATCH", !canonicalEqual(requirements, accepted));
  failures.add(
    "X402_UNSUPPORTED_EXTENSION",
    payload.extensions !== undefined ||
      payload.x402Version !== 2 ||
      requirements.extra.assetTransferMethod !== REQUIRED_TRANSFER_METHOD ||
      requirements.extra.ap2NonceDerivation !== REQUIRED_NONCE_DERIVATION,
  );
  failures.add(
    "X402_MANDATE_REFERENCE_MISMATCH",
    derivedReference !== undefined && requirements.extra.ap2MandateReference !== derivedReference,
  );

  const authorization = payload.payload.authorization;
  for (const [, closed] of mandatePairs) {
    const extension = closed.payment_instrument.x402;
    failures.add(
      "EIP3009_PAYER_MISMATCH",
      extension !== undefined && !addressesEqual(extension.payer, authorization.from),
    );
  }
  failures.add("EIP3009_RECIPIENT_MISMATCH", !addressesEqual(authorization.to, requirements.payTo));
  failures.add("EIP3009_VALUE_MISMATCH", authorization.value !== requirements.amount);

  const now = BigInt(fixtureCase.nowEpochSeconds);
  const validAfter = BigInt(authorization.validAfter);
  const validBefore = BigInt(authorization.validBefore);
  failures.add("EIP3009_VALID_AFTER_IN_FUTURE", validAfter >= now);
  failures.add("EIP3009_VALID_BEFORE_EXPIRED", validBefore < now + EIP3009_SAFETY_BUFFER_SECONDS);
  failures.add(
    "EIP3009_VALIDITY_EXCEEDS_TIMEOUT",
    validBefore > now + BigInt(requirements.maxTimeoutSeconds),
  );
  for (const [open, closed] of mandatePairs) {
    failures.add(
      "EIP3009_VALIDITY_EXCEEDS_AP2_EXPIRY",
      validBefore > BigInt(Math.min(open.exp, closed.exp)),
    );
  }
  let expectedNonce: string | undefined;
  if (derivedReference !== undefined) {
    const decoded = Buffer.from(derivedReference, "base64url");
    if (decoded.byteLength === 32) expectedNonce = `0x${decoded.toString("hex")}`;
  }
  failures.add(
    "EIP3009_NONCE_BINDING_MISMATCH",
    expectedNonce !== undefined && authorization.nonce.toLowerCase() !== expectedNonce,
  );

  const signatureResult = await verifyEip3009Signature({
    network: requirements.network,
    asset: requirements.asset,
    domainName: requirements.extra.name,
    domainVersion: requirements.extra.version,
    authorization,
    signature: payload.payload.signature,
  });
  failures.add("EIP3009_SIGNATURE_INVALID", !signatureResult.valid);

  failures.add("SETTLEMENT_FAILED", !settlement.success);
  failures.add("SETTLEMENT_NETWORK_MISMATCH", settlement.network !== requirements.network);
  failures.add("SETTLEMENT_PAYER_MISMATCH", !addressesEqual(settlement.payer, authorization.from));
  failures.add(
    "SETTLEMENT_AMOUNT_MISMATCH",
    settlement.amount !== undefined && settlement.amount !== requirements.amount,
  );
  failures.add("SETTLEMENT_TRANSACTION_INVALID", !isHex32(settlement.transaction));

  const failureCodes = failures.ordered();
  return {
    id: fixtureCase.id,
    decision: failureCodes.length === 0 ? "accept" : "reject",
    failureCodes,
  };
}

export async function evaluateBundle(
  bundle: ConformanceBundle,
  ap2Verifier: StructuredAp2Verifier,
): Promise<ConformanceResult[]> {
  const results: ConformanceResult[] = [];
  for (const fixtureCase of bundle.cases) {
    results.push(await evaluateCase(fixtureCase, ap2Verifier));
  }
  return results;
}
