import { randomUUID } from "node:crypto";

import {
  hashAction,
  hashCanonical,
  systemClock,
  type ConsumeDecisionResult,
  type InntrisActionV1,
  type InntrisDecisionV1,
  type ReasonCode,
  type ResolveApprovalResult,
} from "@inntris/decision-core";

import {
  assertNoReservedKyaExtension,
  attachKyaAuthorityBinding,
  createRejectedKyaBinding,
  withoutKyaExtension,
} from "./binding.js";
import { asKyaAuthorityError, KyaAuthorityError } from "./errors.js";
import { noOpKyaMetrics } from "./metrics.js";
import type {
  KyaAuthorityGateOptions,
  KyaConsumeInput,
  KyaEvaluateInput,
  KyaResolveApprovalInput,
  VerifiedKyaAuthority,
} from "./types.js";

function rejectedApproval(decisionId: string, reasonCode: ReasonCode): ResolveApprovalResult {
  return {
    success: false,
    status: "rejected",
    decision_id: decisionId,
    reason_code: reasonCode,
  };
}

function rejectedConsumption(
  input: KyaConsumeInput["consumption"],
  reasonCode: ReasonCode,
): ConsumeDecisionResult {
  return {
    success: false,
    status: "rejected",
    decision_id: input.decision_id,
    execution_ref: input.execution_ref,
    reason_code: reasonCode,
  };
}

function sameAuthorityIdentity(
  original: import("./schemas.js").VerifiedKyaAuthorityBindingV1,
  fresh: import("./schemas.js").VerifiedKyaAuthorityBindingV1,
): boolean {
  return (
    original.agent_did === fresh.agent_did &&
    original.responsible_party_did === fresh.responsible_party_did &&
    original.principal_did === fresh.principal_did &&
    original.invocation_target === fresh.invocation_target &&
    original.allowed_action === fresh.allowed_action &&
    original.currency === fresh.currency &&
    original.authority_policy_hash === fresh.authority_policy_hash
  );
}

export class KyaAuthorityGate {
  readonly #clock;
  readonly #metrics;

  constructor(readonly options: KyaAuthorityGateOptions) {
    this.#clock = options.clock ?? systemClock;
    this.#metrics = options.metrics ?? noOpKyaMetrics;
  }

  async protectsDecision(decisionId: string): Promise<boolean> {
    return (await this.options.stateStore.getDecisionAuthority(decisionId)) !== undefined;
  }

  async #issueRejectedBlock(
    action: InntrisActionV1,
    input: KyaEvaluateInput,
    error: KyaAuthorityError,
  ): Promise<InntrisDecisionV1> {
    const clean = withoutKyaExtension(action);
    const rejected =
      input.presentation === undefined
        ? clean
        : attachKyaAuthorityBinding(
            clean,
            createRejectedKyaBinding({
              policy: this.options.authorityPolicy,
              presentation: input.presentation,
              failureStage: error.failureStage,
            }),
          );
    return this.options.provider.issueBlock(rejected, [error.reasonCode]);
  }

  async evaluate(input: KyaEvaluateInput): Promise<InntrisDecisionV1> {
    try {
      assertNoReservedKyaExtension(input.action);
    } catch (error) {
      const failure = asKyaAuthorityError(error);
      this.#metrics.verification("rejected", failure.failureStage);
      const decision = await this.#issueRejectedBlock(input.action, input, failure);
      this.#metrics.authorityGate(decision.verdict);
      return decision;
    }
    if (input.presentation === undefined) {
      if (this.options.authorityPolicy.mode === "required") {
        this.#metrics.verification("rejected", "presentation");
        const decision = await this.options.provider.issueBlock(input.action, [
          "KYA_AUTHORITY_REQUIRED",
        ]);
        this.#metrics.authorityGate(decision.verdict);
        return decision;
      }
      const decision = await this.options.provider.evaluate(input.action);
      this.#metrics.authorityGate(decision.verdict);
      return decision;
    }

    let verified: VerifiedKyaAuthority;
    try {
      verified = await this.options.verifier.verify({
        presentation: input.presentation,
        action: input.action,
        authorityPolicy: this.options.authorityPolicy,
        expectedAudience:
          input.presentation.profile === "legacy-v1"
            ? input.presentation.audience
            : (this.options.authorityPolicy.expected_audiences[0] ?? ""),
        now: this.#clock.now(),
      });
    } catch (error) {
      const failure = asKyaAuthorityError(error);
      this.#metrics.verification("rejected", failure.failureStage);
      if (failure.reasonCode === "KYA_PROOF_REPLAYED") this.#metrics.proofReplay();
      if (
        failure.failureStage === "delegation" ||
        failure.failureStage === "delegation_signature"
      ) {
        this.#metrics.delegationRejection(failure.reasonCode);
      }
      if (failure.failureStage === "revocation") {
        this.#metrics.revocationFailure(failure.reasonCode);
      }
      const decision = await this.#issueRejectedBlock(input.action, input, failure);
      this.#metrics.authorityGate(decision.verdict);
      return decision;
    }

    this.#metrics.verification("verified", "complete");
    const boundAction = attachKyaAuthorityBinding(input.action, verified.binding);
    const decision = await this.options.provider.evaluate(boundAction);
    try {
      await this.options.stateStore.saveDecisionAuthority({
        decision_id: decision.decision_id,
        action_hash: decision.action_hash,
        action: boundAction,
        binding: verified.binding,
        created_at: this.#clock.now().toISOString(),
      });
    } catch (error) {
      throw new KyaAuthorityError(
        "KYA_AUTHORITY_STATE_UNAVAILABLE",
        "state",
        "KYA decision authority could not be persisted",
        { cause: error },
      );
    }
    this.#metrics.authorityGate(decision.verdict);
    return decision;
  }

  async #verifyFresh(
    action: InntrisActionV1,
    presentation: KyaResolveApprovalInput["presentation"],
  ): Promise<VerifiedKyaAuthority> {
    return this.options.verifier.verify({
      presentation,
      action: withoutKyaExtension(action),
      authorityPolicy: this.options.authorityPolicy,
      expectedAudience:
        presentation.profile === "legacy-v1"
          ? presentation.audience
          : (this.options.authorityPolicy.expected_audiences[0] ?? ""),
      now: this.#clock.now(),
    });
  }

  async resolveApproval(input: KyaResolveApprovalInput): Promise<ResolveApprovalResult> {
    const stored = await this.options.stateStore
      .getDecisionAuthority(input.approval.decision_id)
      .catch(() => undefined);
    if (stored === undefined) {
      return rejectedApproval(input.approval.decision_id, "KYA_AUTHORITY_STATE_UNAVAILABLE");
    }

    let fresh: VerifiedKyaAuthority;
    try {
      fresh = await this.#verifyFresh(stored.action, input.presentation);
      if (!sameAuthorityIdentity(stored.binding, fresh.binding)) {
        throw new KyaAuthorityError(
          "KYA_AUTHORITY_BINDING_MISMATCH",
          "financial_join",
          "Fresh KYA authority does not match the original accountable authority",
        );
      }
    } catch (error) {
      const failure = asKyaAuthorityError(error);
      await this.options.stateStore.appendRevalidation({
        id: randomUUID(),
        decision_id: input.approval.decision_id,
        action_hash: stored.action_hash,
        kind: "approval",
        execution_ref: null,
        approval_reference: input.approval.approval_reference,
        presentation_hash: hashCanonical(input.presentation),
        authority_hash: null,
        status: "rejected",
        reason_code: failure.reasonCode,
        verified_at: this.#clock.now().toISOString(),
      });
      this.#metrics.revalidation("approval", "rejected");
      return rejectedApproval(input.approval.decision_id, failure.reasonCode);
    }

    await this.options.stateStore.appendRevalidation({
      id: randomUUID(),
      decision_id: input.approval.decision_id,
      action_hash: stored.action_hash,
      kind: "approval",
      execution_ref: null,
      approval_reference: input.approval.approval_reference,
      presentation_hash: fresh.binding.presentation_hash,
      authority_hash: fresh.binding.authority_hash,
      status: "verified",
      reason_code: null,
      verified_at: this.#clock.now().toISOString(),
    });
    this.#metrics.revalidation("approval", "verified");
    const reboundAction = attachKyaAuthorityBinding(
      withoutKyaExtension(stored.action),
      fresh.binding,
    );
    const result = await this.options.provider.resolveApprovalWithAction(
      input.approval,
      reboundAction,
    );
    if (result.decision !== undefined) {
      await this.options.stateStore.saveDecisionAuthority({
        decision_id: result.decision.decision_id,
        action_hash: result.decision.action_hash,
        action: reboundAction,
        binding: fresh.binding,
        created_at: this.#clock.now().toISOString(),
      });
    }
    return result;
  }

  async consume(input: KyaConsumeInput): Promise<ConsumeDecisionResult> {
    const stored = await this.options.stateStore
      .getDecisionAuthority(input.consumption.decision_id)
      .catch(() => undefined);
    if (stored === undefined) {
      return rejectedConsumption(input.consumption, "KYA_AUTHORITY_STATE_UNAVAILABLE");
    }
    if (
      stored.action_hash !== input.consumption.action_hash ||
      hashAction(stored.action) !== stored.action_hash
    ) {
      return rejectedConsumption(input.consumption, "ACTION_HASH_MISMATCH");
    }
    const prior = await this.options.stateStore.getSuccessfulExecutionRevalidation({
      decisionId: input.consumption.decision_id,
      actionHash: input.consumption.action_hash,
      executionRef: input.consumption.execution_ref,
    });
    if (prior !== undefined) return this.options.provider.consume(input.consumption);

    let fresh: VerifiedKyaAuthority;
    try {
      fresh = await this.#verifyFresh(stored.action, input.presentation);
      if (!sameAuthorityIdentity(stored.binding, fresh.binding)) {
        throw new KyaAuthorityError(
          "KYA_AUTHORITY_BINDING_MISMATCH",
          "financial_join",
          "Fresh KYA authority does not match the decision authority",
        );
      }
    } catch (error) {
      const failure = asKyaAuthorityError(error);
      await this.options.stateStore.appendRevalidation({
        id: randomUUID(),
        decision_id: input.consumption.decision_id,
        action_hash: input.consumption.action_hash,
        kind: "consumption",
        execution_ref: input.consumption.execution_ref,
        approval_reference: null,
        presentation_hash: hashCanonical(input.presentation),
        authority_hash: null,
        status: "rejected",
        reason_code: failure.reasonCode,
        verified_at: this.#clock.now().toISOString(),
      });
      this.#metrics.revalidation("consumption", "rejected");
      return rejectedConsumption(input.consumption, failure.reasonCode);
    }

    await this.options.stateStore.appendRevalidation({
      id: randomUUID(),
      decision_id: input.consumption.decision_id,
      action_hash: input.consumption.action_hash,
      kind: "consumption",
      execution_ref: input.consumption.execution_ref,
      approval_reference: null,
      presentation_hash: fresh.binding.presentation_hash,
      authority_hash: fresh.binding.authority_hash,
      status: "verified",
      reason_code: null,
      verified_at: this.#clock.now().toISOString(),
    });
    this.#metrics.revalidation("consumption", "verified");
    return this.options.provider.consume(input.consumption);
  }
}
