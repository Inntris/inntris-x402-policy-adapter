import type { InntrisActionV1, InntrisDecisionV1 } from "@inntris/decision-core";

import type { EvmUnsignedTransaction } from "./types.js";

export interface CompletedEvmExecution {
  bindingHash: string;
  executionRef: string;
  action: InntrisActionV1;
  decision: InntrisDecisionV1;
  unsignedTransaction: EvmUnsignedTransaction;
  signedTransaction: string;
  transactionHash: string;
}

export type EvmExecutionClaim =
  | { status: "claimed" }
  | { status: "in_progress" }
  | { status: "conflict" }
  | ({ status: "completed" } & CompletedEvmExecution);

export interface EvmExecutionStore {
  claim(input: {
    unsignedTransactionHash: string;
    bindingHash: string;
    executionRef: string;
  }): Promise<EvmExecutionClaim>;
  complete(
    input: {
      unsignedTransactionHash: string;
    } & CompletedEvmExecution,
  ): Promise<void>;
}

type StoredExecution =
  | ({ state: "in_progress" } & Pick<CompletedEvmExecution, "bindingHash" | "executionRef">)
  | ({ state: "completed" } & CompletedEvmExecution);

export class InMemoryEvmExecutionStore implements EvmExecutionStore {
  readonly #executions = new Map<string, StoredExecution>();

  async claim(input: {
    unsignedTransactionHash: string;
    bindingHash: string;
    executionRef: string;
  }): Promise<EvmExecutionClaim> {
    const existing = this.#executions.get(input.unsignedTransactionHash);
    if (existing === undefined) {
      this.#executions.set(input.unsignedTransactionHash, {
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
    return existing.state === "in_progress"
      ? { status: "in_progress" }
      : {
          status: "completed",
          bindingHash: existing.bindingHash,
          executionRef: existing.executionRef,
          action: existing.action,
          decision: existing.decision,
          unsignedTransaction: existing.unsignedTransaction,
          signedTransaction: existing.signedTransaction,
          transactionHash: existing.transactionHash,
        };
  }

  async complete(
    input: {
      unsignedTransactionHash: string;
    } & CompletedEvmExecution,
  ): Promise<void> {
    const existing = this.#executions.get(input.unsignedTransactionHash);
    if (
      existing?.state !== "in_progress" ||
      existing.bindingHash !== input.bindingHash ||
      existing.executionRef !== input.executionRef
    ) {
      throw new Error("EVM execution was not claimed with the same binding");
    }
    this.#executions.set(input.unsignedTransactionHash, {
      state: "completed",
      bindingHash: input.bindingHash,
      executionRef: input.executionRef,
      action: input.action,
      decision: input.decision,
      unsignedTransaction: input.unsignedTransaction,
      signedTransaction: input.signedTransaction,
      transactionHash: input.transactionHash,
    });
  }
}
