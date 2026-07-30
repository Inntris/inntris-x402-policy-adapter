import {
  A2A_ACTION_EXTENSION_KEY,
  InntrisA2ASettlementGate,
  InntrisA2ASettlementGateError,
  verifyA2AActionReceipt,
  type A2AExecutionStore,
  type A2APaymentSubmission,
  type A2ASettlementObservation,
  type A2ASettlementProvider,
  type A2ATaskReference,
} from "@inntris/a2a-settlement-gate";
import { createPublicDemoSigner } from "@inntris/decision-core";
import { paymentRequirementsHash } from "@inntris/x402-adapter";
import { describe, expect, it, vi } from "vitest";

import { bindingInput, requirements, testContext } from "../helpers.js";

const task: A2ATaskReference = {
  id: "task-A",
  contextId: "context-A",
};

function paymentSubmission(overrides: Partial<A2APaymentSubmission> = {}): A2APaymentSubmission {
  return {
    version: "inntris-a2a-payment-submission-v1",
    state: "PAYMENT_SUBMITTED",
    submission_id: "submission-A",
    task_id: task.id,
    context_id: task.contextId,
    resource: bindingInput.resource,
    payment_requirements_hash: paymentRequirementsHash(requirements),
    submitted_at: "2026-07-29T12:00:00.000Z",
    settlement_ref: null,
    ...overrides,
  };
}

function settlement(overrides: Partial<A2ASettlementObservation> = {}): A2ASettlementObservation {
  return {
    version: "inntris-a2a-settlement-observation-v1",
    state: "SETTLED",
    task_id: task.id,
    context_id: task.contextId,
    payment_submission_id: "submission-A",
    payment_requirements_hash: paymentRequirementsHash(requirements),
    resource: bindingInput.resource,
    settlement_ref: "settlement-A",
    finality: "FINAL",
    observed_at: "2026-07-29T12:00:00.000Z",
    evidence: {
      transaction_hash: "0xabc",
      confirmations: 12,
    },
    ...overrides,
  };
}

async function gateContext(
  observation: A2ASettlementObservation = settlement(),
  executionStore?: A2AExecutionStore,
) {
  const context = await testContext();
  const settleMock = vi.fn(async () => observation);
  const confirmMock = vi.fn(async () => observation);
  const settlementProvider: A2ASettlementProvider = {
    settle: settleMock,
    confirm: confirmMock,
  };
  const gate = new InntrisA2ASettlementGate({
    guard: context.guard,
    settlementProvider,
    receiptSigner: createPublicDemoSigner(),
    requiredFinality: "FINAL",
    executionStore,
    clock: context.clock,
  });
  return {
    ...context,
    gate,
    settleMock,
    confirmMock,
  };
}

function gateReason(reasonCode: string): { name: string; reasonCode: string } {
  return {
    name: "InntrisA2ASettlementGateError",
    reasonCode,
  };
}

describe("A2A settlement gate", () => {
  it("never treats PAYMENT_SUBMITTED as settlement", async () => {
    const context = await gateContext(
      settlement({
        state: "PAYMENT_SUBMITTED",
        settlement_ref: null,
        finality: null,
      }),
    );
    const delegate = vi.fn(async () => ({ ok: true }));

    await expect(
      context.gate.process(
        {
          task,
          paymentSubmission: paymentSubmission(),
          payment: bindingInput,
        },
        delegate,
      ),
    ).rejects.toMatchObject(gateReason("SETTLEMENT_NOT_FINAL"));
    expect(delegate).not.toHaveBeenCalled();
  });

  it("pauses when settlement state is UNKNOWN", async () => {
    const context = await gateContext(
      settlement({
        state: "UNKNOWN",
        settlement_ref: null,
        finality: null,
      }),
    );
    const delegate = vi.fn(async () => ({ ok: true }));

    await expect(
      context.gate.process(
        {
          task,
          paymentSubmission: paymentSubmission(),
          payment: bindingInput,
        },
        delegate,
      ),
    ).rejects.toMatchObject(gateReason("SETTLEMENT_UNKNOWN"));
    expect(delegate).not.toHaveBeenCalled();
  });

  it("does not let settlement for task A unlock task B", async () => {
    const context = await gateContext(settlement({ task_id: "task-B" }));
    const delegate = vi.fn(async () => ({ ok: true }));

    await expect(
      context.gate.process(
        {
          task,
          paymentSubmission: paymentSubmission(),
          payment: bindingInput,
        },
        delegate,
      ),
    ).rejects.toMatchObject(gateReason("SETTLEMENT_BINDING_MISMATCH"));
    expect(delegate).not.toHaveBeenCalled();
  });

  it("rejects settlement evidence for different payment requirements", async () => {
    const context = await gateContext(
      settlement({
        payment_requirements_hash:
          "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      }),
    );
    const delegate = vi.fn(async () => ({ ok: true }));

    await expect(
      context.gate.process(
        {
          task,
          paymentSubmission: paymentSubmission(),
          payment: bindingInput,
        },
        delegate,
      ),
    ).rejects.toMatchObject(gateReason("SETTLEMENT_BINDING_MISMATCH"));
    expect(delegate).not.toHaveBeenCalled();
  });

  it("rejects settlement below the configured finality", async () => {
    const context = await gateContext(settlement({ finality: "PROVISIONAL" }));
    const delegate = vi.fn(async () => ({ ok: true }));

    await expect(
      context.gate.process(
        {
          task,
          paymentSubmission: paymentSubmission(),
          payment: bindingInput,
        },
        delegate,
      ),
    ).rejects.toMatchObject(gateReason("SETTLEMENT_NOT_FINAL"));
    expect(delegate).not.toHaveBeenCalled();
  });

  it("rejects a payment submission that does not match the x402 challenge", async () => {
    const context = await gateContext();
    const delegate = vi.fn(async () => ({ ok: true }));

    await expect(
      context.gate.process(
        {
          task,
          paymentSubmission: paymentSubmission({
            payment_requirements_hash:
              "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
          }),
          payment: bindingInput,
        },
        delegate,
      ),
    ).rejects.toMatchObject(gateReason("PAYMENT_BINDING_MISMATCH"));
    expect(context.settleMock).not.toHaveBeenCalled();
    expect(delegate).not.toHaveBeenCalled();
  });

  it("executes the delegate once and returns the signed receipt on retry", async () => {
    const context = await gateContext();
    const delegate = vi.fn(async () => ({ delivered: "artifact-A" }));
    const input = {
      task,
      paymentSubmission: paymentSubmission(),
      payment: bindingInput,
    };

    const first = await context.gate.process(input, delegate);
    const retry = await context.gate.process(input, delegate);

    expect(first.replayed).toBe(false);
    expect(retry.replayed).toBe(true);
    expect(delegate).toHaveBeenCalledTimes(1);
    expect(retry.receipt).toEqual(first.receipt);
    expect(retry.result).toEqual(first.result);
    expect(verifyA2AActionReceipt(first.receipt, context.keyRegistry)).toMatchObject({
      valid: true,
      checks: {
        schema: true,
        fingerprint: true,
        key: true,
        signature: true,
      },
    });

    const tampered = {
      ...first.receipt,
      task_id: "task-B",
    };
    expect(verifyA2AActionReceipt(tampered, context.keyRegistry).valid).toBe(false);
  });

  it("uses confirmation instead of settlement when a settlement reference exists", async () => {
    const context = await gateContext();
    const delegate = vi.fn(async () => ({ ok: true }));

    await context.gate.process(
      {
        task,
        paymentSubmission: paymentSubmission({ settlement_ref: "settlement-A" }),
        payment: bindingInput,
      },
      delegate,
    );

    expect(context.settleMock).not.toHaveBeenCalled();
    expect(context.confirmMock).toHaveBeenCalledTimes(1);
  });

  it("rejects confirmation evidence for another settlement reference", async () => {
    const context = await gateContext(settlement({ settlement_ref: "settlement-B" }));
    const delegate = vi.fn(async () => ({ ok: true }));

    await expect(
      context.gate.process(
        {
          task,
          paymentSubmission: paymentSubmission({ settlement_ref: "settlement-A" }),
          payment: bindingInput,
        },
        delegate,
      ),
    ).rejects.toMatchObject(gateReason("SETTLEMENT_BINDING_MISMATCH"));
    expect(delegate).not.toHaveBeenCalled();
  });

  it("does not call the settlement provider when Inntris returns BLOCK", async () => {
    const context = await gateContext();
    const delegate = vi.fn(async () => ({ ok: true }));
    const blockedPayment = {
      ...bindingInput,
      paymentRequirements: {
        ...bindingInput.paymentRequirements,
        amount: "150000000",
      },
    };

    await expect(
      context.gate.process(
        {
          task,
          paymentSubmission: paymentSubmission({
            payment_requirements_hash: paymentRequirementsHash(blockedPayment.paymentRequirements),
          }),
          payment: blockedPayment,
        },
        delegate,
      ),
    ).rejects.toMatchObject(gateReason("DECISION_NOT_ALLOW"));
    expect(context.settleMock).not.toHaveBeenCalled();
    expect(delegate).not.toHaveBeenCalled();
  });

  it("blocks the delegate when decision consumption fails", async () => {
    const context = await gateContext();
    vi.spyOn(context.provider, "consume").mockResolvedValue({
      success: false,
      status: "conflict",
      decision_id: "decision-A",
      execution_ref: "execution-A",
      reason_code: "NONCE_ALREADY_CONSUMED",
    });
    const delegate = vi.fn(async () => ({ ok: true }));

    await expect(
      context.gate.process(
        {
          task,
          paymentSubmission: paymentSubmission(),
          payment: bindingInput,
        },
        delegate,
      ),
    ).rejects.toMatchObject(gateReason("DECISION_CONSUMPTION_FAILED"));
    expect(delegate).not.toHaveBeenCalled();
  });

  it("pauses a retry after an unresolved delegate failure", async () => {
    const context = await gateContext();
    const failingDelegate = vi.fn(async () => {
      throw new Error("delegate outcome unknown");
    });
    const retryDelegate = vi.fn(async () => ({ shouldNotRun: true }));
    const input = {
      task,
      paymentSubmission: paymentSubmission(),
      payment: bindingInput,
    };

    await expect(context.gate.process(input, failingDelegate)).rejects.toMatchObject(
      gateReason("DELEGATE_EXECUTION_FAILED"),
    );
    await expect(context.gate.process(input, retryDelegate)).rejects.toMatchObject(
      gateReason("DELEGATE_EXECUTION_IN_PROGRESS"),
    );
    expect(failingDelegate).toHaveBeenCalledTimes(1);
    expect(retryDelegate).not.toHaveBeenCalled();
  });

  it("pauses before delegation when execution state cannot be claimed", async () => {
    const executionStore: A2AExecutionStore = {
      claim: vi.fn(async () => {
        throw new Error("store unavailable");
      }),
      complete: vi.fn(async () => undefined),
    };
    const context = await gateContext(settlement(), executionStore);
    const delegate = vi.fn(async () => ({ shouldNotRun: true }));

    await expect(
      context.gate.process(
        {
          task,
          paymentSubmission: paymentSubmission(),
          payment: bindingInput,
        },
        delegate,
      ),
    ).rejects.toMatchObject(gateReason("DELEGATE_EXECUTION_STORE_UNAVAILABLE"));
    expect(delegate).not.toHaveBeenCalled();
  });

  it("requires reconciliation when completed execution state cannot be finalised", async () => {
    const executionStore: A2AExecutionStore = {
      claim: vi.fn(async () => ({ status: "claimed" })),
      complete: vi.fn(async () => {
        throw new Error("store unavailable");
      }),
    };
    const context = await gateContext(settlement(), executionStore);
    const delegate = vi.fn(async () => ({ delivered: true }));

    await expect(
      context.gate.process(
        {
          task,
          paymentSubmission: paymentSubmission(),
          payment: bindingInput,
        },
        delegate,
      ),
    ).rejects.toMatchObject(gateReason("DELEGATE_EXECUTION_STORE_UNAVAILABLE"));
    expect(delegate).toHaveBeenCalledTimes(1);
  });

  it("binds A2A task identity into the Inntris action hash", async () => {
    const context = await testContext();
    const binding = {
      version: "inntris-a2a-binding-v1",
      task_id: "task-A",
      context_id: "context-A",
      payment_submission_id: "submission-A",
      payment_requirements_hash: paymentRequirementsHash(requirements),
      resource: bindingInput.resource,
      required_finality: "FINAL",
    };
    const decisionA = await context.guard.authorise({
      ...bindingInput,
      extensions: {
        [A2A_ACTION_EXTENSION_KEY]: binding,
      },
    });
    const decisionB = await context.guard.authorise({
      ...bindingInput,
      extensions: {
        [A2A_ACTION_EXTENSION_KEY]: {
          ...binding,
          task_id: "task-B",
        },
      },
    });

    expect(decisionA.action_hash).not.toBe(decisionB.action_hash);
  });

  it("exposes a typed gate error", () => {
    expect(new InntrisA2ASettlementGateError("blocked", "SETTLEMENT_UNKNOWN")).toBeInstanceOf(
      Error,
    );
  });
});
