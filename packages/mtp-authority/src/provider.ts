import type {
  ConsumeDecisionInput,
  ConsumeDecisionResult,
  DecisionProvider,
  InntrisActionV1,
  InntrisDecisionV1,
} from "@inntris/decision-core";

import { MtpAuthorityClient, MtpConsumptionRejectedError } from "./client.js";
import type { MtpAuthorityStateStore } from "./types.js";

export interface MtpCompositeDecisionProviderOptions {
  provider: DecisionProvider;
  client: MtpAuthorityClient;
  stateStore: MtpAuthorityStateStore;
  clock?: { now(): Date } | undefined;
}

function reject(
  input: ConsumeDecisionInput,
  reason:
    | "DECISION_NOT_ALLOW"
    | "DECISION_SERVICE_UNAVAILABLE"
    | "NONCE_ALREADY_CONSUMED"
    | "ACTION_HASH_MISMATCH",
): ConsumeDecisionResult {
  return {
    success: false,
    status: reason === "NONCE_ALREADY_CONSUMED" ? "conflict" : "rejected",
    decision_id: input.decision_id,
    execution_ref: input.execution_ref,
    reason_code: reason,
  };
}

/**
 * Requires both the signed Decision Envelope and MTP authority before execution.
 * MTP is consumed first and checkpointed before the local decision is consumed.
 * Settlement remains outside this class and is called only by the rail guard.
 */
export class MtpCompositeDecisionProvider implements DecisionProvider {
  readonly #clock: { now(): Date };

  constructor(readonly options: MtpCompositeDecisionProviderOptions) {
    this.#clock = options.clock ?? { now: () => new Date() };
  }

  async evaluate(action: InntrisActionV1): Promise<InntrisDecisionV1> {
    const decision = await this.options.provider.evaluate(action);
    if (decision.verdict !== "ALLOW") return decision;
    const authorization = await this.options.client.authorize(action, decision);
    await this.options.stateStore.saveAuthorization(authorization);
    return decision;
  }

  async consume(input: ConsumeDecisionInput): Promise<ConsumeDecisionResult> {
    if (input.execution_ref.trim() === "" || input.execution_ref.length > 512) {
      return reject(input, "DECISION_NOT_ALLOW");
    }
    let authorization = await this.options.stateStore.getAuthorization(input.decision_id);
    if (authorization === undefined) {
      return reject(input, "DECISION_SERVICE_UNAVAILABLE");
    }
    if (authorization.actionHash !== input.action_hash) {
      return reject(input, "ACTION_HASH_MISMATCH");
    }
    const claim = await this.options.stateStore.claimExecution(
      input.decision_id,
      input.action_hash,
      input.execution_ref,
    );
    if (claim === "missing") return reject(input, "DECISION_SERVICE_UNAVAILABLE");
    if (claim === "conflict") return reject(input, "NONCE_ALREADY_CONSUMED");

    authorization = await this.options.stateStore.getAuthorization(input.decision_id);
    if (authorization === undefined) return reject(input, "DECISION_SERVICE_UNAVAILABLE");
    if (authorization.consumptionAuditId === undefined) {
      try {
        const receipt = await this.options.client.consume(authorization, input.execution_ref);
        await this.options.stateStore.markMtpConsumed(
          input.decision_id,
          input.execution_ref,
          receipt,
        );
      } catch (error) {
        if (error instanceof MtpConsumptionRejectedError) {
          return reject(input, "DECISION_NOT_ALLOW");
        }
        throw error;
      }
    }

    const result = await this.options.provider.consume(input);
    if (result.success) {
      await this.options.stateStore.markComplete(
        input.decision_id,
        input.execution_ref,
        this.#clock.now().toISOString(),
      );
    }
    return result;
  }
}
