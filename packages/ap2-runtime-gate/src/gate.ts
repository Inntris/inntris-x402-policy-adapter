import {
  hashCanonical,
  type Clock,
  type DecisionProvider,
  type InntrisActionV1,
  type InntrisDecisionV1,
  type KeyRegistry,
  type SigningProvider,
} from "@inntris/decision-core";
import { verifyDecision } from "@inntris/decision-verifier";
import { z } from "zod";

import { actionFromAP2 } from "./binding.js";
import { createAP2ActionReceipt } from "./receipt.js";
import { InMemoryAP2ExecutionStore, type AP2ExecutionStore } from "./store.js";
import {
  AP2MandatePresentationSchema,
  AP2OfficialVerificationRequestSchema,
  AP2OfficialVerificationSchema,
  AP2_OFFICIAL_SDK_COMMIT,
  AP2_OFFICIAL_REPOSITORY,
  type AP2Delegate,
  type AP2GateReasonCode,
  type AP2OfficialVerification,
  type AP2RuntimeGateInput,
  type AP2RuntimeGateResult,
  type AP2TrustProvider,
  type AP2OfficialVerifier,
} from "./types.js";

const AP2GateInputSchema = z
  .object({
    mandates: AP2MandatePresentationSchema,
    principalId: z.string().min(1).max(128),
    agentId: z.string().min(1).max(128),
    resource: z.url(),
    purpose: z.string().min(1).max(128),
    expectedMerchantId: z.string().min(1).max(128),
    expectedAmountMinor: z.string().regex(/^(0|[1-9]\d*)$/u),
    expectedCurrency: z.string().regex(/^[A-Z]{3}$/u),
    extensions: z.record(z.string(), z.unknown()).optional(),
  })
  .strict();

export interface InntrisAP2RuntimeGateOptions {
  provider: DecisionProvider;
  keyRegistry: KeyRegistry;
  verifier: AP2OfficialVerifier;
  trustProvider: AP2TrustProvider;
  receiptSigner: SigningProvider;
  executionStore?: AP2ExecutionStore;
  expectedPolicyVersion?: string;
  maxVerificationAgeSeconds?: number;
  currencyDecimals: Readonly<Record<string, number>>;
  clock?: Clock;
}

export class InntrisAP2RuntimeGateError extends Error {
  override readonly name = "InntrisAP2RuntimeGateError";

  constructor(
    message: string,
    readonly reasonCode: AP2GateReasonCode,
    readonly causeCode?: string,
  ) {
    super(message);
  }
}

function reject(message: string, reasonCode: AP2GateReasonCode, causeCode?: string): never {
  throw new InntrisAP2RuntimeGateError(message, reasonCode, causeCode);
}

function requireCurrentVerification(
  verification: AP2OfficialVerification,
  now: Date,
  maxAgeSeconds: number,
): void {
  const verifiedAt = Date.parse(verification.verified_at);
  const age = now.getTime() - verifiedAt;
  if (age < 0 || age > maxAgeSeconds * 1_000) {
    reject("Official AP2 verification is stale or from the future", "AP2_VERIFICATION_STALE");
  }
  if (
    now.getTime() >= Date.parse(verification.checkout.expires_at) ||
    now.getTime() >= Date.parse(verification.payment.expires_at)
  ) {
    reject("An AP2 mandate has expired", "AP2_MANDATE_EXPIRED");
  }
}

function requireExactBinding(
  input: AP2RuntimeGateInput,
  verification: AP2OfficialVerification,
): void {
  if (!verification.intent.verified) {
    reject("AP2 autonomous intent constraints were not verified", "AP2_INTENT_INVALID");
  }
  if (
    verification.checkout.merchant_id !== input.expectedMerchantId ||
    verification.payment.payee_id !== input.expectedMerchantId ||
    verification.checkout.merchant_id !== verification.payment.payee_id
  ) {
    reject(
      "AP2 checkout and payment mandates are bound to a different merchant",
      "AP2_CHECKOUT_BINDING_MISMATCH",
    );
  }
  if (
    verification.payment.amount_minor !== input.expectedAmountMinor ||
    verification.payment.currency !== input.expectedCurrency ||
    verification.payment.transaction_id !== verification.checkout.checkout_hash
  ) {
    reject(
      "AP2 payment amount, currency, or checkout reference differs from execution",
      "AP2_PAYMENT_BINDING_MISMATCH",
    );
  }
}

export class InntrisAP2RuntimeGate {
  readonly #clock: Clock;
  readonly #currencyDecimals: ReadonlyMap<string, number>;
  readonly #executionStore: AP2ExecutionStore;
  readonly #maxVerificationAgeSeconds: number;

  constructor(readonly options: InntrisAP2RuntimeGateOptions) {
    this.#clock = options.clock ?? { now: () => new Date() };
    this.#currencyDecimals = new Map(Object.entries(options.currencyDecimals));
    this.#executionStore = options.executionStore ?? new InMemoryAP2ExecutionStore();
    this.#maxVerificationAgeSeconds = options.maxVerificationAgeSeconds ?? 30;
    if (
      !Number.isInteger(this.#maxVerificationAgeSeconds) ||
      this.#maxVerificationAgeSeconds < 1 ||
      this.#maxVerificationAgeSeconds > 300
    ) {
      throw new TypeError("maxVerificationAgeSeconds must be an integer from 1 to 300");
    }
    for (const [currency, decimals] of this.#currencyDecimals) {
      if (
        !/^[A-Z]{3}$/u.test(currency) ||
        !Number.isInteger(decimals) ||
        decimals < 0 ||
        decimals > 18
      ) {
        throw new TypeError(
          "currencyDecimals must map ISO currency codes to integers from 0 to 18",
        );
      }
    }
  }

  async process<T>(
    inputValue: AP2RuntimeGateInput,
    executeDelegate: AP2Delegate<T>,
  ): Promise<AP2RuntimeGateResult<T>> {
    const parsedInput = AP2GateInputSchema.safeParse(inputValue);
    if (!parsedInput.success) {
      return reject("AP2 runtime input is invalid", "INVALID_AP2_INPUT");
    }
    const input = parsedInput.data;
    const now = this.#clock.now();
    let trust;
    try {
      trust = await this.options.trustProvider.resolve(input.expectedMerchantId);
    } catch (error) {
      return reject(
        "AP2 trust material is unavailable",
        "AP2_TRUST_UNAVAILABLE",
        error instanceof Error ? error.name : undefined,
      );
    }

    const request = AP2OfficialVerificationRequestSchema.parse({
      ...input.mandates,
      issuer_public_jwk: trust.issuerPublicJwk,
      merchant_public_jwk: trust.merchantPublicJwk,
      expected_merchant_id: input.expectedMerchantId,
      current_time_epoch: Math.floor(now.getTime() / 1_000),
    });
    let rawVerification: unknown;
    try {
      rawVerification = await this.options.verifier.verify(request);
    } catch (error) {
      return reject(
        "Official AP2 SDK verification failed closed",
        "AP2_VERIFICATION_FAILED",
        error instanceof Error ? error.name : undefined,
      );
    }
    const verificationResult = AP2OfficialVerificationSchema.safeParse(rawVerification);
    if (!verificationResult.success) {
      const rawSdk = (rawVerification as { sdk?: { repository?: unknown; commit?: unknown } })?.sdk;
      if (
        rawSdk?.repository !== AP2_OFFICIAL_REPOSITORY ||
        rawSdk.commit !== AP2_OFFICIAL_SDK_COMMIT
      ) {
        return reject(
          "AP2 verifier provenance does not match the pinned official SDK",
          "AP2_SDK_PROVENANCE_MISMATCH",
        );
      }
      return reject("AP2 verifier returned invalid evidence", "AP2_VERIFICATION_FAILED");
    }
    const verification = verificationResult.data;
    requireCurrentVerification(verification, now, this.#maxVerificationAgeSeconds);
    requireExactBinding(input, verification);
    const currencyDecimals = this.#currencyDecimals.get(verification.payment.currency);
    if (currencyDecimals === undefined) {
      return reject(
        "The AP2 payment currency has no operator configured minor unit mapping",
        "INVALID_AP2_INPUT",
      );
    }

    let action: InntrisActionV1;
    try {
      action = actionFromAP2(input, verification, currencyDecimals);
    } catch (error) {
      return reject(
        "AP2 evidence could not be bound to an Inntris action",
        "INVALID_AP2_INPUT",
        error instanceof Error ? error.name : undefined,
      );
    }

    let decision: InntrisDecisionV1;
    try {
      decision = await this.options.provider.evaluate(action);
    } catch (error) {
      return reject(
        "Inntris policy evaluation failed closed",
        "DECISION_INVALID",
        error instanceof Error ? error.name : undefined,
      );
    }
    const decisionVerification = verifyDecision({
      decision,
      action,
      keyRegistry: this.options.keyRegistry,
      at: this.#clock.now(),
      expectedPolicyVersion: this.options.expectedPolicyVersion,
    });
    if (!decisionVerification.valid) {
      return reject(
        "Inntris returned a decision that could not be verified",
        "DECISION_INVALID",
        decisionVerification.reason_codes.join(","),
      );
    }
    if (decision.verdict !== "ALLOW") {
      return reject(
        "Current organisational policy did not allow the AP2 payment",
        "DECISION_NOT_ALLOW",
      );
    }

    requireCurrentVerification(verification, this.#clock.now(), this.#maxVerificationAgeSeconds);
    const executionRef = `ap2-execution:${hashCanonical({
      version: "inntris-ap2-execution-ref-v1",
      checkout_mandate_hash: verification.checkout.mandate_hash,
      payment_mandate_hash: verification.payment.mandate_hash,
      action_hash: decision.action_hash,
    }).slice(7)}`;
    let consumption;
    try {
      consumption = await this.options.provider.consume({
        decision_id: decision.decision_id,
        action_hash: decision.action_hash,
        execution_ref: executionRef,
      });
    } catch (error) {
      return reject(
        "Inntris decision consumption is unavailable; AP2 execution is blocked",
        "DECISION_CONSUMPTION_FAILED",
        error instanceof Error ? error.name : undefined,
      );
    }
    if (!consumption.success) {
      return reject(
        "Inntris decision consumption failed; AP2 execution is blocked",
        "DECISION_CONSUMPTION_FAILED",
        consumption.reason_code,
      );
    }

    const bindingHash = hashCanonical({
      version: "inntris-ap2-execution-binding-v1",
      intent_verification_hash:
        action.protocol_reference.type === "ap2"
          ? action.protocol_reference.intent_verification_hash
          : null,
      checkout_mandate_hash: verification.checkout.mandate_hash,
      payment_mandate_hash: verification.payment.mandate_hash,
      action_hash: decision.action_hash,
    });
    let claim;
    try {
      claim = await this.#executionStore.claim({
        paymentMandateHash: verification.payment.mandate_hash,
        bindingHash,
        executionRef,
      });
    } catch (error) {
      return reject(
        "AP2 execution state is unavailable; automatic execution is paused",
        "AP2_EXECUTION_STORE_UNAVAILABLE",
        error instanceof Error ? error.name : undefined,
      );
    }
    if (claim.status === "conflict") {
      return reject(
        "The AP2 Payment Mandate was already bound to a different execution",
        "AP2_EXECUTION_CONFLICT",
      );
    }
    if (claim.status === "in_progress") {
      return reject(
        "The AP2 Payment Mandate has an unresolved execution attempt",
        "AP2_EXECUTION_IN_PROGRESS",
      );
    }
    if (claim.status === "completed") {
      return {
        action: claim.action,
        decision: claim.decision,
        verification: claim.verification,
        execution_ref: claim.executionRef,
        receipt: claim.receipt,
        result: claim.result as T,
        replayed: true,
      };
    }

    let result: T;
    try {
      result = await executeDelegate({
        action,
        decision,
        verification,
        executionRef,
      });
    } catch (error) {
      return reject(
        "AP2 delegate failed after execution was claimed; reconciliation is required",
        "AP2_DELEGATE_FAILED",
        error instanceof Error ? error.name : undefined,
      );
    }

    let receipt;
    try {
      receipt = await createAP2ActionReceipt({
        action,
        decision,
        verification,
        executionRef,
        delegateResult: result,
        signer: this.options.receiptSigner,
        executedAt: this.#clock.now(),
      });
    } catch (error) {
      return reject(
        "AP2 delegate completed but its receipt could not be signed",
        "AP2_RECEIPT_SIGNING_FAILED",
        error instanceof Error ? error.name : undefined,
      );
    }
    try {
      await this.#executionStore.complete({
        paymentMandateHash: verification.payment.mandate_hash,
        bindingHash,
        executionRef,
        action,
        decision,
        verification,
        receipt,
        result,
      });
    } catch (error) {
      return reject(
        "AP2 delegate completed but execution state could not be finalised",
        "AP2_EXECUTION_STORE_UNAVAILABLE",
        error instanceof Error ? error.name : undefined,
      );
    }
    return {
      action,
      decision,
      verification,
      execution_ref: executionRef,
      receipt,
      result,
      replayed: false,
    };
  }
}
