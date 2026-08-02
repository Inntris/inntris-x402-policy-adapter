import {
  InMemoryNonceStore,
  createSignedDecision,
  hashPolicyObject,
  noOpMetrics,
  systemClock,
  type Clock,
  type ConsumeDecisionInput,
  type ConsumeDecisionResult,
  type DecisionProvider,
  type InntrisActionV1,
  type InntrisDecisionV1,
  type MetricsRecorder,
  type NonceStore,
  type ReasonCode,
  type ResolveApprovalInput,
  type ResolveApprovalResult,
  type SigningProvider,
  type UnsignedEvaluation,
} from "@inntris/decision-core";

import { evaluatePolicy, spendDayKey, ZeroSpendState, type SpendState } from "./evaluate.js";
import { InMemoryDecisionStateStore, type DecisionStateStore } from "./decision-store.js";
import { DEFAULT_APPROVAL_REQUEST_TTL_SECONDS, type InntrisPolicyV1 } from "./policy.js";
import type { AtomicPolicyStateStore } from "./state-store.js";

export interface LocalPolicyDecisionProviderOptions {
  policy: InntrisPolicyV1;
  signer: SigningProvider;
  clock?: Clock;
  spendState?: SpendState;
  nonceStore?: NonceStore;
  decisionStore?: DecisionStateStore;
  stateStore?: AtomicPolicyStateStore;
  metrics?: MetricsRecorder;
}

export class LocalPolicyDecisionProvider implements DecisionProvider {
  readonly policyHash: string;
  readonly #clock: Clock;
  readonly #spendState: SpendState;
  readonly #nonceStore: NonceStore;
  readonly #decisionStore: DecisionStateStore;
  readonly #stateStore: AtomicPolicyStateStore | undefined;
  readonly #metrics: MetricsRecorder;

  constructor(readonly options: LocalPolicyDecisionProviderOptions) {
    if (
      options.stateStore !== undefined &&
      (options.spendState !== undefined ||
        options.nonceStore !== undefined ||
        options.decisionStore !== undefined)
    ) {
      throw new Error("stateStore cannot be combined with spendState, nonceStore or decisionStore");
    }
    this.policyHash = hashPolicyObject(options.policy);
    this.#clock = options.clock ?? systemClock;
    this.#stateStore = options.stateStore;
    this.#spendState = options.stateStore ?? options.spendState ?? new ZeroSpendState();
    this.#nonceStore = options.nonceStore ?? new InMemoryNonceStore();
    this.#decisionStore =
      options.stateStore ?? options.decisionStore ?? new InMemoryDecisionStateStore();
    this.#metrics = options.metrics ?? noOpMetrics;
  }

  async #sign(
    action: InntrisActionV1,
    evaluation: UnsignedEvaluation,
    supersedesDecisionId?: string,
  ): Promise<InntrisDecisionV1> {
    const decision = await createSignedDecision({
      action,
      evaluation,
      policyHash: this.policyHash,
      policyVersion: this.options.policy.policy_version,
      decisionTtlSeconds: this.options.policy.defaults.decision_ttl_seconds,
      signer: this.options.signer,
      clock: this.#clock,
      ...(supersedesDecisionId === undefined ? {} : { supersedesDecisionId }),
    });
    await this.#decisionStore.save({ decision, action });
    return decision;
  }

  async evaluate(action: InntrisActionV1): Promise<InntrisDecisionV1> {
    const started = performance.now();
    const evaluation = await evaluatePolicy({
      action,
      policy: this.options.policy,
      spendState: this.#spendState,
      clock: this.#clock,
    });
    const decision = await this.#sign(action, evaluation);
    this.#metrics.decision(decision.verdict, decision.rail, performance.now() - started);
    return decision;
  }

  /**
   * Issues a new decision that supersedes an open `REQUIRE_APPROVAL` decision.
   * The original decision is never mutated, and current organisational policy
   * is re-evaluated, so a human grant cannot override a policy that now denies
   * the same action.
   */
  async resolveApproval(input: ResolveApprovalInput): Promise<ResolveApprovalResult> {
    const rejection = (reasonCode: ReasonCode): ResolveApprovalResult => ({
      success: false,
      status: reasonCode === "APPROVAL_ALREADY_RESOLVED" ? "conflict" : "rejected",
      decision_id: input.decision_id,
      reason_code: reasonCode,
    });

    const issued = await this.#decisionStore.get(input.decision_id);
    if (issued?.decision.verdict !== "REQUIRE_APPROVAL") {
      return rejection("APPROVAL_NOT_PENDING");
    }

    const requestTtlSeconds =
      this.options.policy.approval.request_ttl_seconds ?? DEFAULT_APPROVAL_REQUEST_TTL_SECONDS;
    const closesAt = Date.parse(issued.decision.issued_at) + requestTtlSeconds * 1_000;
    if (this.#clock.now().getTime() >= closesAt) {
      return rejection("DECISION_EXPIRED");
    }

    const claim = await this.#decisionStore.claimApproval(input.decision_id);
    if (claim === "already_claimed") {
      return rejection("APPROVAL_ALREADY_RESOLVED");
    }

    const started = performance.now();
    const policyEvaluation = await evaluatePolicy({
      action: issued.action,
      policy: this.options.policy,
      spendState: this.#spendState,
      clock: this.#clock,
    });
    const approval = {
      mode: "human" as const,
      approval_reference: input.approval_reference,
      approver_ids: input.approver_ids,
    };
    let evaluation: UnsignedEvaluation;
    if (!input.granted) {
      evaluation = { verdict: "BLOCK", reasonCodes: ["HUMAN_APPROVAL_REFUSED"], approval };
    } else if (policyEvaluation.verdict === "BLOCK") {
      evaluation = { ...policyEvaluation, approval };
    } else {
      evaluation = {
        verdict: "ALLOW",
        reasonCodes: [
          ...policyEvaluation.reasonCodes.filter((code) => code !== "HUMAN_APPROVAL_REQUIRED"),
          "HUMAN_APPROVAL_GRANTED",
        ],
        approval,
      };
    }

    const decision = await this.#sign(issued.action, evaluation, issued.decision.decision_id);
    this.#metrics.decision(decision.verdict, decision.rail, performance.now() - started);
    return {
      success: true,
      status: "superseded",
      decision_id: input.decision_id,
      decision,
    };
  }

  async consume(input: ConsumeDecisionInput): Promise<ConsumeDecisionResult> {
    const decision = (await this.#decisionStore.get(input.decision_id))?.decision;
    if (decision?.verdict !== "ALLOW") {
      return {
        success: false,
        status: "rejected",
        decision_id: input.decision_id,
        execution_ref: input.execution_ref,
        reason_code: "DECISION_NOT_ALLOW",
      };
    }
    if (decision.action_hash !== input.action_hash) {
      return {
        success: false,
        status: "rejected",
        decision_id: input.decision_id,
        execution_ref: input.execution_ref,
        reason_code: "ACTION_HASH_MISMATCH",
      };
    }
    const now = this.#clock.now();
    if (now.getTime() >= Date.parse(decision.expires_at)) {
      return {
        success: false,
        status: "rejected",
        decision_id: input.decision_id,
        execution_ref: input.execution_ref,
        reason_code: "DECISION_EXPIRED",
      };
    }
    const consumption = {
      decisionId: decision.decision_id,
      nonce: decision.nonce,
      actionHash: decision.action_hash,
      executionRef: input.execution_ref,
      expiresAt: new Date(decision.expires_at),
      consumedAt: now,
    };
    const spend = {
      principalId: decision.principal_id,
      dayKey: spendDayKey(now, this.options.policy.time_windows.timezone),
      amount: decision.transaction.amount,
    };
    const result =
      this.#stateStore === undefined
        ? await this.#nonceStore.consume(consumption)
        : await this.#stateStore.consumeAndRecordSpend({
            consumption,
            spend,
            dailyLimit: this.options.policy.limits.daily,
          });
    if (result.status === "conflict") {
      this.#metrics.replayAttempt();
    }
    /** Legacy split stores remain available for reference integrations. Only
     * a first, unique consumption adds to their cumulative daily total. The
     * atomic state store performs both operations inside its own transaction.
     */
    if (this.#stateStore === undefined && result.status === "consumed") {
      await this.#spendState.recordSpend(spend);
    }
    return result;
  }
}
