import type {
  ConsumeDecisionInput,
  ConsumeDecisionResult,
  BlockDecisionIssuer,
  BoundApprovalDecisionProvider,
  DecisionProvider,
  InntrisActionV1,
  InntrisDecisionV1,
  ReasonCode,
  ResolveApprovalInput,
  ResolveApprovalResult,
} from "@inntris/decision-core";
import { InntrisActionV1Schema } from "@inntris/decision-core";

import { MtpAuthorityClient, MtpConsumptionRejectedError } from "./client.js";
import type { MtpAuthorityStateStore } from "./types.js";

export interface MtpCompositeDecisionProviderOptions {
  provider: DecisionProvider & BlockDecisionIssuer & BoundApprovalDecisionProvider;
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
export class MtpCompositeDecisionProvider
  implements DecisionProvider, BlockDecisionIssuer, BoundApprovalDecisionProvider
{
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

  async issueBlock(action: InntrisActionV1, reasonCodes: ReasonCode[]): Promise<InntrisDecisionV1> {
    return this.options.provider.issueBlock(action, reasonCodes);
  }

  async #authoriseApprovalResult(
    action: InntrisActionV1,
    result: ResolveApprovalResult,
  ): Promise<ResolveApprovalResult> {
    if (result.decision?.verdict === "ALLOW") {
      const authorization = await this.options.client.authorize(action, result.decision);
      await this.options.stateStore.saveAuthorization(authorization);
    }
    return result;
  }

  async resolveApproval(input: ResolveApprovalInput): Promise<ResolveApprovalResult> {
    const result = await this.options.provider.resolveApproval?.(input);
    if (result === undefined) {
      return {
        success: false,
        status: "rejected",
        decision_id: input.decision_id,
        reason_code: "APPROVAL_NOT_PENDING",
      };
    }
    const decision = result.decision;
    if (decision === undefined) return result;
    const action = InntrisActionV1Schema.parse({
      version: "inntris-action-v1",
      principal_id: decision.principal_id,
      agent_id: decision.agent_id,
      action_type: decision.action_type,
      rail: decision.rail,
      protocol_reference: decision.protocol_reference,
      transaction: decision.transaction,
    });
    return this.#authoriseApprovalResult(action, result);
  }

  async resolveApprovalWithAction(
    input: ResolveApprovalInput,
    action: InntrisActionV1,
  ): Promise<ResolveApprovalResult> {
    const result = await this.options.provider.resolveApprovalWithAction(input, action);
    return this.#authoriseApprovalResult(action, result);
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
