import {
  ExecutionReconciliationError,
  InMemoryExecutionReconciliationStore,
  executionOperationId,
} from "@inntris/execution-reconciliation";
import { describe, expect, it, vi } from "vitest";

import { bindingInput, MutableClock, testContext } from "../helpers.js";

const actionHash = `sha256:${"a".repeat(64)}`;
const bindingHash = `sha256:${"b".repeat(64)}`;

function prepareInput(clock = new MutableClock()) {
  return {
    rail: "x402" as const,
    operationKind: "x402_settlement" as const,
    decisionId: "decision-reconciliation-1",
    actionHash,
    executionRef: "execution-reconciliation-1",
    bindingHash,
    preparedAt: clock.now(),
  };
}

describe("execution reconciliation", () => {
  it("claims once, blocks unresolved retries and accepts authoritative resolution", async () => {
    const clock = new MutableClock();
    const store = new InMemoryExecutionReconciliationStore();
    const prepared = await store.prepare(prepareInput(clock));
    expect(prepared.operationId).toBe(executionOperationId(prepareInput(clock)));
    expect((await store.prepare(prepareInput(clock))).operationId).toBe(prepared.operationId);

    const starts = await Promise.all([
      store.start({ operationId: prepared.operationId, bindingHash, startedAt: clock.now() }),
      store.start({ operationId: prepared.operationId, bindingHash, startedAt: clock.now() }),
    ]);
    expect(starts.map((result) => result.status).sort()).toEqual(["claimed", "in_progress"]);

    await store.markOutcomeUnknown({
      operationId: prepared.operationId,
      bindingHash,
      errorCode: "TimeoutError",
      observedAt: clock.now(),
    });
    expect(
      (
        await store.start({
          operationId: prepared.operationId,
          bindingHash,
          startedAt: clock.now(),
        })
      ).status,
    ).toBe("outcome_unknown");
    expect(await store.listUnresolved()).toHaveLength(1);

    const resolved = await store.resolve({
      operationId: prepared.operationId,
      bindingHash,
      outcome: "succeeded",
      outcomeReference: "base-sepolia:0xsettlement",
      resolvedBy: "operator-1",
      resolutionNote: "Confirmed through the facilitator and chain receipt",
      resolvedAt: clock.now(),
    });
    expect(resolved).toMatchObject({
      status: "succeeded",
      resolvedBy: "operator-1",
      outcomeReference: "base-sepolia:0xsettlement",
    });
    expect(await store.listUnresolved()).toEqual([]);
  });

  it("rejects changed bindings and incomplete final-failure resolutions", async () => {
    const store = new InMemoryExecutionReconciliationStore();
    const prepared = await store.prepare(prepareInput());
    await expect(
      store.prepare({ ...prepareInput(), bindingHash: `sha256:${"c".repeat(64)}` }),
    ).rejects.toBeInstanceOf(ExecutionReconciliationError);
    await store.start({ operationId: prepared.operationId, bindingHash, startedAt: new Date() });
    await store.markOutcomeUnknown({
      operationId: prepared.operationId,
      bindingHash,
      errorCode: "TimeoutError",
      observedAt: new Date(),
    });
    await expect(
      store.resolve({
        operationId: prepared.operationId,
        bindingHash,
        outcome: "failed_final",
        outcomeReference: "facilitator:rejected",
        resolvedBy: "operator-1",
        resolutionNote: "Final rejection confirmed",
        resolvedAt: new Date(),
      }),
    ).rejects.toThrow("requires an error code");
    expect(await store.get(prepared.operationId)).toMatchObject({
      status: "outcome_unknown",
      resolvedBy: null,
    });
  });

  it("validates transition evidence before mutating operation state", async () => {
    const store = new InMemoryExecutionReconciliationStore();
    const prepared = await store.prepare({
      ...prepareInput(),
      executionRef: "execution-invalid-evidence",
    });
    await store.start({ operationId: prepared.operationId, bindingHash, startedAt: new Date() });
    await expect(
      store.markSucceeded({
        operationId: prepared.operationId,
        bindingHash,
        outcomeReference: "x".repeat(513),
        resolvedAt: new Date(),
      }),
    ).rejects.toThrow();
    expect(await store.get(prepared.operationId)).toMatchObject({
      status: "in_progress",
      outcomeReference: null,
    });
  });

  it("journals successful x402 settlement and blocks a duplicate external call", async () => {
    const store = new InMemoryExecutionReconciliationStore();
    const context = await testContext(new MutableClock(), { reconciliationStore: store });
    const decision = await context.guard.authorise(bindingInput);
    const settle = vi.fn(async () => "settled");

    await expect(
      context.guard.settleIfAuthorised(bindingInput, decision, "journal-success", settle),
    ).resolves.toBe("settled");
    expect(settle).toHaveBeenCalledOnce();
    expect(await store.listUnresolved()).toEqual([]);

    await expect(
      context.guard.settleIfAuthorised(bindingInput, decision, "journal-success", settle),
    ).rejects.toMatchObject({ reasonCodes: ["EXECUTION_ALREADY_COMPLETED"] });
    expect(settle).toHaveBeenCalledOnce();
  });

  it("records an unknown x402 outcome and blocks automatic retry", async () => {
    const store = new InMemoryExecutionReconciliationStore();
    const context = await testContext(new MutableClock(), { reconciliationStore: store });
    const decision = await context.guard.authorise(bindingInput);
    const settle = vi.fn(async () => {
      const error = new Error("facilitator timeout");
      error.name = "TimeoutError";
      throw error;
    });

    await expect(
      context.guard.settleIfAuthorised(bindingInput, decision, "journal-unknown", settle),
    ).rejects.toMatchObject({ reasonCodes: ["EXECUTION_OUTCOME_UNKNOWN"] });
    expect((await store.listUnresolved())[0]).toMatchObject({
      status: "outcome_unknown",
      lastErrorCode: "TimeoutError",
    });

    await expect(
      context.guard.settleIfAuthorised(bindingInput, decision, "journal-unknown", settle),
    ).rejects.toMatchObject({ reasonCodes: ["EXECUTION_OUTCOME_UNKNOWN"] });
    expect(settle).toHaveBeenCalledOnce();
  });

  it("distinguishes a classified final failure from an uncertain outcome", async () => {
    const store = new InMemoryExecutionReconciliationStore();
    const context = await testContext(new MutableClock(), {
      reconciliationStore: store,
      classifySettlementError: () => "failed_final",
    });
    const decision = await context.guard.authorise(bindingInput);

    await expect(
      context.guard.settleIfAuthorised(bindingInput, decision, "journal-final", async () => {
        throw new Error("facilitator rejected before submission");
      }),
    ).rejects.toMatchObject({ reasonCodes: ["EXECUTION_FAILED_FINAL"] });
    expect(await store.listUnresolved()).toEqual([]);
  });

  it("fails closed before settlement when the journal is unavailable", async () => {
    const store = new InMemoryExecutionReconciliationStore();
    vi.spyOn(store, "prepare").mockRejectedValueOnce(new Error("database unavailable"));
    const context = await testContext(new MutableClock(), { reconciliationStore: store });
    const decision = await context.guard.authorise(bindingInput);
    const settle = vi.fn(async () => "settled");

    await expect(
      context.guard.settleIfAuthorised(bindingInput, decision, "journal-down", settle),
    ).rejects.toMatchObject({ reasonCodes: ["EXECUTION_STATE_UNAVAILABLE"] });
    expect(settle).not.toHaveBeenCalled();
  });

  it("requires reconciliation if settlement succeeds but journal finalisation fails", async () => {
    const store = new InMemoryExecutionReconciliationStore();
    vi.spyOn(store, "markSucceeded").mockRejectedValueOnce(new Error("database unavailable"));
    const context = await testContext(new MutableClock(), { reconciliationStore: store });
    const decision = await context.guard.authorise(bindingInput);
    const settle = vi.fn(async () => "settled");

    await expect(
      context.guard.settleIfAuthorised(bindingInput, decision, "journal-finalise", settle),
    ).rejects.toMatchObject({ reasonCodes: ["RECONCILIATION_REQUIRED"] });
    expect(settle).toHaveBeenCalledOnce();
    expect((await store.listUnresolved())[0]?.status).toBe("in_progress");
  });
});
