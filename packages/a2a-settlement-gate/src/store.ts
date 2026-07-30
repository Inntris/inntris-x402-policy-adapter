import type { A2AActionReceipt } from "./types.js";

export interface CompletedA2AExecution {
  bindingHash: string;
  receipt: A2AActionReceipt;
  result: unknown;
}

export type A2AExecutionClaim =
  | { status: "claimed" }
  | { status: "in_progress" }
  | { status: "conflict" }
  | ({ status: "completed" } & CompletedA2AExecution);

export interface A2AExecutionStore {
  claim(input: { executionRef: string; bindingHash: string }): Promise<A2AExecutionClaim>;
  complete(
    input: { executionRef: string; bindingHash: string } & Omit<
      CompletedA2AExecution,
      "bindingHash"
    >,
  ): Promise<void>;
}

type StoredExecution =
  { state: "in_progress"; bindingHash: string } | ({ state: "completed" } & CompletedA2AExecution);

export class InMemoryA2AExecutionStore implements A2AExecutionStore {
  readonly #executions = new Map<string, StoredExecution>();

  async claim(input: { executionRef: string; bindingHash: string }): Promise<A2AExecutionClaim> {
    const existing = this.#executions.get(input.executionRef);
    if (existing === undefined) {
      this.#executions.set(input.executionRef, {
        state: "in_progress",
        bindingHash: input.bindingHash,
      });
      return { status: "claimed" };
    }
    if (existing.bindingHash !== input.bindingHash) {
      return { status: "conflict" };
    }
    if (existing.state === "in_progress") {
      return { status: "in_progress" };
    }
    return {
      status: "completed",
      bindingHash: existing.bindingHash,
      receipt: existing.receipt,
      result: existing.result,
    };
  }

  async complete(
    input: { executionRef: string; bindingHash: string } & Omit<
      CompletedA2AExecution,
      "bindingHash"
    >,
  ): Promise<void> {
    const existing = this.#executions.get(input.executionRef);
    if (existing?.state !== "in_progress" || existing.bindingHash !== input.bindingHash) {
      throw new Error("A2A execution was not claimed with the same binding");
    }
    this.#executions.set(input.executionRef, {
      state: "completed",
      bindingHash: input.bindingHash,
      receipt: input.receipt,
      result: input.result,
    });
  }
}
