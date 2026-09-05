import { canonicalBytes } from "@inntris/decision-core";
import { createHash } from "node:crypto";
import { privateKeyToAccount } from "viem/accounts";

import {
  AP2_COMMIT,
  EIP3009_AUTHORIZATION_TYPES,
  EXPECTED_AP2_VERIFIER,
  PULSE_CASE_VERSION,
  REQUIRED_NONCE_DERIVATION,
  X402_COMMIT,
  X402_PACKAGE_VERSION,
  calculateInputHash,
  sha256Base64Url,
  type ConformanceCase,
  type StructuredAp2Verification,
  type StructuredAp2Verifier,
} from "../../packages/pulse-conformance-evaluator/src/index.js";

const TEST_PRIVATE_KEY = "0x0000000000000000000000000000000000000000000000000000000000000001";
const account = privateKeyToAccount(TEST_PRIVATE_KEY);

function hash(value: unknown): string {
  return createHash("sha256").update(canonicalBytes(value)).digest("base64url");
}

function canonicalTestBase64Url(character: string): string {
  return `${character.repeat(42)}A`;
}

export async function makeConformanceCase(): Promise<ConformanceCase> {
  const now = 2_000_000_000;
  const issuerJwt = "eyJhbGciOiJFUzI1NiJ9.eyJ0ZXN0Ijp0cnVlfQ.signature";
  const mandateReference = sha256Base64Url(issuerJwt);
  const nonce = `0x${Buffer.from(mandateReference, "base64url").toString("hex")}`;
  const asset = "0x0000000000000000000000000000000000000001";
  const payTo = "0x000000000000000000000000000000000000dEaD";
  const amount = "1250000";
  const transaction = `0x${"12".repeat(32)}`;
  const extension = {
    version: 2,
    scheme: "exact",
    network: "eip155:31337",
    asset,
    amount,
    payTo,
    payer: account.address,
    ap2PayeeId: "merchant-test",
    ap2PaymentAmount: { amount: 1250, currency: "GBP" },
    maxTimeoutSeconds: 300,
    eip712Domain: { name: "Synthetic GBP", version: "2" },
    nonceBinding: REQUIRED_NONCE_DERIVATION,
  };
  const instrument = {
    id: "test-eip3009",
    type: "x402",
    description: "Independent test instrument",
    x402: extension,
  };
  const openMandate = {
    vct: "mandate.payment.open.1",
    constraints: [
      { type: "payment.reference", conditional_transaction_id: "A".repeat(43) },
      { type: "payment.allowed_payment_instruments", allowed: [instrument] },
      { type: "payment.amount_range", currency: "GBP", min: 1250, max: 1250 },
      {
        type: "payment.allowed_payees",
        allowed: [
          {
            id: "merchant-test",
            name: "Merchant display alias",
            website: "https://alias.example",
          },
        ],
      },
    ],
    cnf: {
      jwk: {
        kty: "EC",
        crv: "P-256",
        alg: "ES256",
        kid: "test-holder",
        x: canonicalTestBase64Url("A"),
        y: canonicalTestBase64Url("B"),
      },
    },
    iat: now - 120,
    exp: now + 300,
  };
  const closedMandate = {
    vct: "mandate.payment.1",
    transaction_id: "A".repeat(43),
    payee: {
      id: "merchant-test",
      name: "Merchant legal display",
      website: "https://merchant.example",
    },
    payment_amount: { amount: 1250, currency: "GBP" },
    payment_instrument: instrument,
    execution_date: "2033-05-18T03:33:20Z",
    iat: now - 60,
    exp: now + 300,
  };
  const receipt = {
    status: "Success",
    iss: "facilitator.example",
    iat: now,
    reference: mandateReference,
    error: null,
    error_description: null,
    payment_id: "payment-test",
    psp_confirmation_id: "psp-test",
    network_confirmation_id: transaction,
  };
  const requirements = {
    scheme: "exact",
    network: "eip155:31337",
    asset,
    amount,
    payTo,
    maxTimeoutSeconds: 300,
    extra: {
      name: "Synthetic GBP",
      version: "2",
      assetTransferMethod: "eip3009",
      ap2MandateReference: mandateReference,
      ap2NonceDerivation: REQUIRED_NONCE_DERIVATION,
    },
  };
  const authorization = {
    from: account.address,
    to: payTo,
    value: amount,
    validAfter: String(now - 30),
    validBefore: String(now + 300),
    nonce,
  };
  const signature = await account.signTypedData({
    domain: {
      name: requirements.extra.name,
      version: requirements.extra.version,
      chainId: 31337n,
      verifyingContract: asset,
    },
    types: EIP3009_AUTHORIZATION_TYPES,
    primaryType: "TransferWithAuthorization",
    message: {
      from: account.address,
      to: payTo,
      value: BigInt(amount),
      validAfter: BigInt(authorization.validAfter),
      validBefore: BigInt(authorization.validBefore),
      nonce,
    },
  });
  const fixtureCase = {
    caseVersion: PULSE_CASE_VERSION,
    sourcePins: {
      ap2Commit: AP2_COMMIT,
      x402Commit: X402_COMMIT,
      x402PackageVersion: X402_PACKAGE_VERSION,
    },
    id: "independent-test-case",
    description: "Independent evaluator test input",
    nowEpochSeconds: now,
    ap2: {
      closedMandate,
      openMandate,
      paymentReceipt: receipt,
      verification: {
        verifier: EXPECTED_AP2_VERIFIER,
        verifiedAtEpochSeconds: now,
        clockSkewSeconds: 0,
        openCheckoutReference: "A".repeat(43),
        closedMandateClaimsHash: hash(closedMandate),
        openMandateClaimsHash: hash(openMandate),
        closedMandateReference: mandateReference,
        cryptographicEvidence: {
          mandateChain: "synthetic-chain-not-consumed-by-mock",
          paymentReceiptJwt: "synthetic-receipt-not-consumed-by-mock",
          trustedRootPublicJwk: {
            kty: "EC",
            crv: "P-256",
            alg: "ES256",
            kid: "root",
            x: canonicalTestBase64Url("C"),
            y: canonicalTestBase64Url("D"),
          },
          trustedReceiptPublicJwk: {
            kty: "EC",
            crv: "P-256",
            alg: "ES256",
            kid: "receipt",
            x: canonicalTestBase64Url("E"),
            y: canonicalTestBase64Url("F"),
          },
          expectedAudience: "https://facilitator.example/ap2",
          expectedNonce: "test-nonce",
        },
      },
    },
    x402: {
      requirements,
      payload: {
        x402Version: 2,
        resource: {
          url: "https://resource.example/report",
          description: "Independent resource",
          mimeType: "application/json",
        },
        accepted: structuredClone(requirements),
        payload: { signature, authorization },
      },
      settlement: {
        success: true,
        payer: account.address,
        transaction,
        network: requirements.network,
      },
    },
    inputHash: "",
  } as ConformanceCase;
  fixtureCase.inputHash = calculateInputHash(fixtureCase);
  return fixtureCase;
}

export function makeMockVerifier(fixtureCase: ConformanceCase): StructuredAp2Verifier {
  const openClaims = structuredClone(fixtureCase.ap2.openMandate);
  const closedClaims = structuredClone(fixtureCase.ap2.closedMandate);
  const paymentReceipt = fixtureCase.ap2.paymentReceipt;
  if (paymentReceipt === undefined) throw new Error("Test receipt setup failed");
  const receiptClaims = structuredClone(paymentReceipt);
  const reference = fixtureCase.ap2.verification.closedMandateReference;
  const issuerJwt = "eyJhbGciOiJFUzI1NiJ9.eyJ0ZXN0Ijp0cnVlfQ.signature";
  if (sha256Base64Url(issuerJwt) !== reference) throw new Error("Test reference setup failed");
  return {
    verify: async (): Promise<StructuredAp2Verification> => ({
      version: "inntris-pulse-ap2-structured-verification/0.1",
      sdk: {
        repository: "https://github.com/google-agentic-commerce/AP2",
        commit: AP2_COMMIT,
        protocolVersion: "0.2",
      },
      openMandate: { status: "verified", claims: openClaims },
      closedMandate: { status: "verified", claims: closedClaims, issuerJwt },
      keyBinding: { status: "verified" },
      mandateTime: { status: "verified" },
      receipt: { status: "verified", claims: receiptClaims },
    }),
  };
}
