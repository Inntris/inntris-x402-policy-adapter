import {
  hashAction,
  type ConsumeDecisionResult,
  type DecisionProvider,
  type InntrisDecisionV1,
  type KeyRegistry,
  type ReasonCode,
} from "@inntris/decision-core";
import { verifyDecision, type VerificationResult } from "@inntris/decision-verifier";
import type { PaymentPayload, PaymentRequirements } from "@x402/core/types";

import { actionFromX402, paymentRequirementsHash, type X402BindingInput } from "./binding.js";

export type X402AuthorisationInput = X402BindingInput;

export interface X402SettlementInput {
  paymentRequirements: PaymentRequirements;
  paymentPayload?: PaymentPayload;
  resource: string;
  principalId: string;
  agentId: string;
  purpose: string;
  assetDecimals: number;
  extensions?: Record<string, unknown>;
}

export interface InntrisX402GuardOptions {
  provider: DecisionProvider;
  keyRegistry: KeyRegistry;
  expectedPolicyVersion?: string | undefined;
  clock?: { now(): Date } | undefined;
}

export class InntrisGuardError extends Error {
  override readonly name = "InntrisGuardError";

  constructor(
    message: string,
    readonly reasonCodes: ReasonCode[],
  ) {
    super(message);
  }
}

function rejectVerdict(result: VerificationResult): VerificationResult {
  if (!result.valid || result.verdict === "ALLOW") {
    return result;
  }
  return {
    ...result,
    valid: false,
    reason_codes: [...result.reason_codes, "DECISION_NOT_ALLOW"],
  };
}

export class InntrisX402Guard {
  readonly #clock: { now(): Date };

  constructor(readonly options: InntrisX402GuardOptions) {
    this.#clock = options.clock ?? { now: () => new Date() };
  }

  async authorise(input: X402AuthorisationInput): Promise<InntrisDecisionV1> {
    const action = actionFromX402(input);
    let decision: InntrisDecisionV1;
    try {
      decision = await this.options.provider.evaluate(action);
    } catch {
      throw new InntrisGuardError("Inntris evaluation failed closed", [
        "DECISION_SERVICE_UNAVAILABLE",
      ]);
    }
    const verification = verifyDecision({
      decision,
      action,
      keyRegistry: this.options.keyRegistry,
      at: this.#clock.now(),
      expectedPolicyVersion: this.options.expectedPolicyVersion,
      expectedPaymentRequirementsHash: paymentRequirementsHash(input.paymentRequirements),
    });
    if (!verification.valid) {
      throw new InntrisGuardError(
        "Inntris returned a decision that could not be verified",
        verification.reason_codes,
      );
    }
    return decision;
  }

  async verifyBeforeSettlement(
    input: X402SettlementInput,
    decision: InntrisDecisionV1,
  ): Promise<VerificationResult> {
    let action;
    try {
      action = actionFromX402(input);
    } catch {
      return {
        valid: false,
        checks: {
          schema: false,
          signature: false,
          fingerprint: false,
          action_hash: false,
          decision_binding: false,
          expiry: false,
          policy_version: false,
          payment_requirements: false,
        },
        reason_codes: ["PAYMENT_REQUIREMENTS_MISMATCH"],
      };
    }
    return rejectVerdict(
      verifyDecision({
        decision,
        action,
        keyRegistry: this.options.keyRegistry,
        at: this.#clock.now(),
        expectedPolicyVersion: this.options.expectedPolicyVersion,
        expectedPaymentRequirementsHash: paymentRequirementsHash(input.paymentRequirements),
      }),
    );
  }

  async consumeBeforeExecution(
    decision: InntrisDecisionV1,
    executionRef: string,
  ): Promise<ConsumeDecisionResult> {
    try {
      return await this.options.provider.consume({
        decision_id: decision.decision_id,
        action_hash: decision.action_hash,
        execution_ref: executionRef,
      });
    } catch {
      return {
        success: false,
        status: "rejected",
        decision_id: decision.decision_id,
        execution_ref: executionRef,
        reason_code: "DECISION_SERVICE_UNAVAILABLE",
      };
    }
  }

  async settleIfAuthorised<T>(
    input: X402SettlementInput,
    decision: InntrisDecisionV1,
    executionRef: string,
    settle: () => Promise<T>,
  ): Promise<T> {
    const verification = await this.verifyBeforeSettlement(input, decision);
    if (!verification.valid) {
      throw new InntrisGuardError(
        "Settlement blocked by decision verification",
        verification.reason_codes,
      );
    }

    const currentAction = actionFromX402(input);
    if (hashAction(currentAction) !== decision.action_hash) {
      throw new InntrisGuardError("Settlement action differs from the authorised action", [
        "ACTION_HASH_MISMATCH",
      ]);
    }

    const consumption = await this.consumeBeforeExecution(decision, executionRef);
    if (!consumption.success) {
      throw new InntrisGuardError("Settlement blocked because decision consumption failed", [
        consumption.reason_code ?? "DECISION_NOT_ALLOW",
      ]);
    }

    return settle();
  }
}
