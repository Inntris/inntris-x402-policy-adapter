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
  type SigningProvider,
} from "@inntris/decision-core";

import { evaluatePolicy, ZeroSpendState, type SpendState } from "./evaluate.js";
import type { InntrisPolicyV1 } from "./policy.js";

export interface LocalPolicyDecisionProviderOptions {
  policy: InntrisPolicyV1;
  signer: SigningProvider;
  clock?: Clock;
  spendState?: SpendState;
  nonceStore?: NonceStore;
  metrics?: MetricsRecorder;
}

export class LocalPolicyDecisionProvider implements DecisionProvider {
  readonly policyHash: string;
  readonly #clock: Clock;
  readonly #spendState: SpendState;
  readonly #nonceStore: NonceStore;
  readonly #metrics: MetricsRecorder;
  readonly #decisions = new Map<string, InntrisDecisionV1>();

  constructor(readonly options: LocalPolicyDecisionProviderOptions) {
    this.policyHash = hashPolicyObject(options.policy);
    this.#clock = options.clock ?? systemClock;
    this.#spendState = options.spendState ?? new ZeroSpendState();
    this.#nonceStore = options.nonceStore ?? new InMemoryNonceStore();
    this.#metrics = options.metrics ?? noOpMetrics;
  }

  async evaluate(action: InntrisActionV1): Promise<InntrisDecisionV1> {
    const started = performance.now();
    const evaluation = await evaluatePolicy({
      action,
      policy: this.options.policy,
      spendState: this.#spendState,
      clock: this.#clock,
    });
    const decision = await createSignedDecision({
      action,
      evaluation,
      policyHash: this.policyHash,
      policyVersion: this.options.policy.policy_version,
      decisionTtlSeconds: this.options.policy.defaults.decision_ttl_seconds,
      signer: this.options.signer,
      clock: this.#clock,
    });
    this.#decisions.set(decision.decision_id, decision);
    this.#metrics.decision(decision.verdict, decision.rail, performance.now() - started);
    return decision;
  }

  async consume(input: ConsumeDecisionInput): Promise<ConsumeDecisionResult> {
    const decision = this.#decisions.get(input.decision_id);
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
    const result = await this.#nonceStore.consume({
      decisionId: decision.decision_id,
      nonce: decision.nonce,
      actionHash: decision.action_hash,
      executionRef: input.execution_ref,
      expiresAt: new Date(decision.expires_at),
      consumedAt: now,
    });
    if (result.status === "conflict") {
      this.#metrics.replayAttempt();
    }
    return result;
  }
}
