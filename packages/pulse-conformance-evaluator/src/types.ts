import type { ConformanceFailureCode } from "./failures.js";

export interface SourcePins {
  ap2Commit: string;
  x402Commit: string;
  x402PackageVersion: string;
}

export interface Merchant {
  id: string;
  name: string;
  website: string;
}

export interface Amount {
  amount: number;
  currency: string;
}

export interface Eip712DomainProfile {
  name: string;
  version: string;
}

export interface Ap2X402Extension {
  version: number;
  scheme: string;
  network: string;
  asset: string;
  amount: string;
  payTo: string;
  payer: string;
  ap2PayeeId: string;
  ap2PaymentAmount: Amount;
  maxTimeoutSeconds: number;
  eip712Domain: Eip712DomainProfile;
  nonceBinding: string;
  [key: string]: unknown;
}

export interface PaymentInstrument {
  id: string;
  type: string;
  description: string;
  x402?: Ap2X402Extension | undefined;
}

export interface ClosedMandate {
  vct: string;
  transaction_id: string;
  payee: Merchant;
  payment_amount: Amount;
  payment_instrument: PaymentInstrument;
  execution_date: string;
  iat: number;
  exp: number;
}

export interface PaymentReferenceConstraint {
  type: "payment.reference";
  conditional_transaction_id: string;
}

export interface AllowedPaymentInstrumentsConstraint {
  type: "payment.allowed_payment_instruments";
  allowed: PaymentInstrument[];
}

export interface AmountRangeConstraint {
  type: "payment.amount_range";
  currency: string;
  max: number;
  min: number;
}

export interface AllowedPayeesConstraint {
  type: "payment.allowed_payees";
  allowed: Merchant[];
}

export type PaymentConstraint =
  | PaymentReferenceConstraint
  | AllowedPaymentInstrumentsConstraint
  | AmountRangeConstraint
  | AllowedPayeesConstraint
  | Record<string, unknown>;

export interface OpenMandate {
  vct: string;
  constraints: PaymentConstraint[];
  cnf: { jwk: Record<string, unknown> };
  payee?: Merchant | undefined;
  payment_amount?: Amount | undefined;
  payment_instrument?: PaymentInstrument | undefined;
  execution_date?: string | undefined;
  iat: number;
  exp: number;
}

export interface PaymentReceipt {
  status: string;
  iss: string;
  iat: number;
  reference: string;
  error: string | null;
  error_description: string | null;
  payment_id: string;
  psp_confirmation_id?: string | null | undefined;
  network_confirmation_id?: string | null | undefined;
}

export interface Ap2CryptographicEvidence {
  mandateChain: string;
  paymentReceiptJwt: string;
  trustedRootPublicJwk: Record<string, unknown>;
  trustedReceiptPublicJwk: Record<string, unknown>;
  expectedAudience: string;
  expectedNonce: string;
}

export interface Ap2VerificationRecord {
  verifier: string;
  verifiedAtEpochSeconds: number;
  clockSkewSeconds: number;
  openCheckoutReference: string;
  closedMandateClaimsHash: string;
  openMandateClaimsHash: string;
  closedMandateReference: string;
  cryptographicEvidence: Ap2CryptographicEvidence;
}

export interface Ap2Input {
  closedMandate: ClosedMandate;
  openMandate: OpenMandate;
  paymentReceipt?: PaymentReceipt | undefined;
  verification: Ap2VerificationRecord;
}

export interface X402RequirementsExtra {
  name: string;
  version: string;
  assetTransferMethod: string;
  ap2MandateReference: string;
  ap2NonceDerivation: string;
}

export interface X402Requirements {
  scheme: string;
  network: string;
  asset: string;
  amount: string;
  payTo: string;
  maxTimeoutSeconds: number;
  extra: X402RequirementsExtra;
}

export interface X402Resource {
  url: string;
  description: string;
  mimeType: string;
}

export interface Eip3009Authorization {
  from: string;
  to: string;
  value: string;
  validAfter: string;
  validBefore: string;
  nonce: string;
}

export interface X402Payload {
  x402Version: number;
  resource: X402Resource;
  accepted: X402Requirements;
  payload: {
    signature: string;
    authorization: Eip3009Authorization;
  };
  extensions?: unknown;
}

export interface X402Settlement {
  success: boolean;
  payer: string;
  transaction: string;
  network: string;
  amount?: string | undefined;
  errorReason?: string | undefined;
}

export interface X402Input {
  requirements: X402Requirements;
  payload: X402Payload;
  settlement: X402Settlement;
}

export interface ConformanceCaseEnvelope {
  caseVersion: string;
  sourcePins: SourcePins;
  id: string;
  description: string;
  nowEpochSeconds: number;
  ap2: unknown;
  x402: unknown;
  inputHash: string;
}

export interface ConformanceCase extends ConformanceCaseEnvelope {
  ap2: Ap2Input;
  x402: X402Input;
}

export interface ConformanceBundle {
  bundleVersion: string;
  sourcePins: SourcePins;
  generatedAt: string;
  cases: ConformanceCaseEnvelope[];
}

export interface ConformanceResult {
  id: string;
  decision: "accept" | "reject";
  failureCodes: ConformanceFailureCode[];
}

export type Ap2VerificationStatus = "verified" | "invalid" | "notEvaluated";

export type StructuredClaimsVerification =
  { status: "verified"; claims: Record<string, unknown> } | { status: "invalid" | "notEvaluated" };

export type StructuredClosedMandateVerification =
  | { status: "verified"; claims: Record<string, unknown>; issuerJwt: string }
  | { status: "invalid" | "notEvaluated" };

export interface StructuredAp2Verification {
  version: "inntris-pulse-ap2-structured-verification/0.1";
  sdk: {
    repository: string;
    commit: string;
    protocolVersion: string;
  };
  openMandate: StructuredClaimsVerification;
  closedMandate: StructuredClosedMandateVerification;
  keyBinding: { status: Ap2VerificationStatus };
  mandateTime: { status: Ap2VerificationStatus };
  receipt: StructuredClaimsVerification;
}

export interface StructuredAp2Verifier {
  verify(input: {
    mandateChain: string;
    paymentReceiptJwt: string;
    trustedRootPublicJwk: Record<string, unknown>;
    trustedReceiptPublicJwk: Record<string, unknown>;
    expectedAudience: string;
    expectedNonce: string;
    currentTimeEpoch: number;
    clockSkewSeconds: number;
  }): Promise<StructuredAp2Verification>;
}

export interface ReproductionRecord {
  recordVersion: string;
  performedAt: string;
  implementation: {
    repositoryUrl: string;
    commit: string;
    language: string;
    runtime: string;
    command: string;
    organization: string;
    independentOfPrimeBeat: true;
  };
  fixture: {
    repositoryCommit: string;
    path: string;
    sha256: string;
    caseCount: number;
  };
  environment: {
    operatingSystem: string;
    architecture: string;
    dependencies: string[];
  };
  results: ConformanceResult[];
  notes: string;
  publishedUrl: string;
}
