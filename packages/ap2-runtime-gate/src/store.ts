import type { InntrisActionV1, InntrisDecisionV1 } from "@inntris/decision-core";

import type { AP2ActionReceipt, AP2OfficialVerification } from "./types.js";

export interface CompletedAP2Execution {
  bindingHash: string;
  executionRef: string;
  action: InntrisActionV1;
  decision: InntrisDecisionV1;
  verification: AP2OfficialVerification;
  receipt: AP2ActionReceipt;
  result: unknown;
}

export type AP2ExecutionClaim =
  | { status: "claimed" }
  | { status: "in_progress" }
  | { status: "conflict" }
  | ({ status: "completed" } & CompletedAP2Execution);

export interface AP2ExecutionStore {
  claim(input: {
    paymentMandateHash: string;
    bindingHash: string;
    executionRef: string;
  }): Promise<AP2ExecutionClaim>;
  complete(
    input: {
      paymentMandateHash: string;
    } & CompletedAP2Execution,
  ): Promise<void>;
}

type StoredExecution =
  | ({ state: "in_progress" } & Pick<CompletedAP2Execution, "bindingHash" | "executionRef">)
  | ({ state: "completed" } & CompletedAP2Execution);

export class InMemoryAP2ExecutionStore implements AP2ExecutionStore {
  readonly #executions = new Map<string, StoredExecution>();

  async claim(input: {
    paymentMandateHash: string;
    bindingHash: string;
    executionRef: string;
  }): Promise<AP2ExecutionClaim> {
    const existing = this.#executions.get(input.paymentMandateHash);
    if (existing === undefined) {
      this.#executions.set(input.paymentMandateHash, {
        state: "in_progress",
        bindingHash: input.bindingHash,
        executionRef: input.executionRef,
      });
      return { status: "claimed" };
    }
    if (
      existing.bindingHash !== input.bindingHash ||
      existing.executionRef !== input.executionRef
    ) {
      return { status: "conflict" };
    }
    if (existing.state === "in_progress") {
      return { status: "in_progress" };
    }
    return {
      status: "completed",
      bindingHash: existing.bindingHash,
      executionRef: existing.executionRef,
      action: existing.action,
      decision: existing.decision,
      verification: existing.verification,
      receipt: existing.receipt,
      result: existing.result,
    };
  }

  async complete(
    input: {
      paymentMandateHash: string;
    } & CompletedAP2Execution,
  ): Promise<void> {
    const existing = this.#executions.get(input.paymentMandateHash);
    if (
      existing?.state !== "in_progress" ||
      existing.bindingHash !== input.bindingHash ||
      existing.executionRef !== input.executionRef
    ) {
      throw new Error("AP2 execution was not claimed with the same binding");
    }
    this.#executions.set(input.paymentMandateHash, {
      state: "completed",
      bindingHash: input.bindingHash,
      executionRef: input.executionRef,
      action: input.action,
      decision: input.decision,
      verification: input.verification,
      receipt: input.receipt,
      result: input.result,
    });
  }
}
