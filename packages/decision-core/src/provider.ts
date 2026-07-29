import type { InntrisActionV1, InntrisDecisionV1, ReasonCode } from "./schemas.js";

export interface ConsumeDecisionInput {
  decision_id: string;
  action_hash: string;
  execution_ref: string;
}

export interface ConsumeDecisionResult {
  success: boolean;
  status: "consumed" | "idempotent" | "conflict" | "rejected";
  decision_id: string;
  execution_ref: string;
  consumed_at?: string;
  reason_code?: ReasonCode;
}

export interface DecisionProvider {
  evaluate(input: InntrisActionV1): Promise<InntrisDecisionV1>;
  consume(input: ConsumeDecisionInput): Promise<ConsumeDecisionResult>;
}

export interface NonceConsumption {
  decisionId: string;
  nonce: string;
  actionHash: string;
  executionRef: string;
  expiresAt: Date;
  consumedAt: Date;
}

export interface NonceStore {
  consume(input: NonceConsumption): Promise<ConsumeDecisionResult>;
}

export class InMemoryNonceStore implements NonceStore {
  readonly #consumed = new Map<string, NonceConsumption>();

  async consume(input: NonceConsumption): Promise<ConsumeDecisionResult> {
    const key = `${input.decisionId}:${input.nonce}`;
    const existing = this.#consumed.get(key);

    if (existing === undefined) {
      this.#consumed.set(key, input);
      return {
        success: true,
        status: "consumed",
        decision_id: input.decisionId,
        execution_ref: input.executionRef,
        consumed_at: input.consumedAt.toISOString(),
      };
    }

    if (existing.actionHash === input.actionHash && existing.executionRef === input.executionRef) {
      return {
        success: true,
        status: "idempotent",
        decision_id: input.decisionId,
        execution_ref: input.executionRef,
        consumed_at: existing.consumedAt.toISOString(),
      };
    }

    return {
      success: false,
      status: "conflict",
      decision_id: input.decisionId,
      execution_ref: input.executionRef,
      reason_code: "NONCE_ALREADY_CONSUMED",
    };
  }
}
