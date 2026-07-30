import {
  hashCanonical,
  type Clock,
  type InntrisDecisionV1,
  type SigningProvider,
} from "@inntris/decision-core";
import {
  InntrisX402Guard,
  paymentRequirementsHash,
  type X402SettlementInput,
} from "@inntris/x402-adapter";

import { createA2AActionReceipt } from "./receipt.js";
import { InMemoryA2AExecutionStore, type A2AExecutionStore } from "./store.js";
import {
  A2A_ACTION_EXTENSION_KEY,
  A2AActionBindingSchema,
  A2AFinalityRequirementSchema,
  A2APaymentSubmissionSchema,
  A2ASettlementObservationSchema,
  type A2AActionBinding,
  type A2ADelegate,
  type A2AGateReasonCode,
  type A2APaymentSubmission,
  type A2ASettlementGateInput,
  type A2ASettlementGateResult,
  type A2ASettlementObservation,
  type A2ASettlementProvider,
  type A2ATaskReference,
} from "./types.js";

export interface InntrisA2ASettlementGateOptions {
  guard: InntrisX402Guard;
  settlementProvider: A2ASettlementProvider;
  receiptSigner: SigningProvider;
  requiredFinality: string;
  executionStore?: A2AExecutionStore;
  clock?: Clock;
}

export class InntrisA2ASettlementGateError extends Error {
  override readonly name = "InntrisA2ASettlementGateError";

  constructor(
    message: string,
    readonly reasonCode: A2AGateReasonCode,
    readonly causeCode?: string,
  ) {
    super(message);
  }
}

interface PreparedInput {
  task: A2ATaskReference;
  paymentSubmission: A2APaymentSubmission;
  payment: X402SettlementInput;
  binding: A2AActionBinding;
  requiredFinality: string;
}

function reject(message: string, reasonCode: A2AGateReasonCode, causeCode?: string): never {
  throw new InntrisA2ASettlementGateError(message, reasonCode, causeCode);
}

function prepareInput(input: A2ASettlementGateInput, requiredFinality: string): PreparedInput {
  const task = {
    id: input.task.id,
    contextId: input.task.contextId,
  };
  const taskResult = A2AActionBindingSchema.shape.task_id.safeParse(task.id);
  const contextResult = A2AActionBindingSchema.shape.context_id.safeParse(task.contextId);
  const submissionResult = A2APaymentSubmissionSchema.safeParse(input.paymentSubmission);
  const finalityResult = A2AFinalityRequirementSchema.safeParse(requiredFinality);
  if (
    !taskResult.success ||
    !contextResult.success ||
    !submissionResult.success ||
    !finalityResult.success
  ) {
    return reject(
      "A2A task, payment submission, or finality input is invalid",
      "INVALID_A2A_INPUT",
    );
  }
  const submission = submissionResult.data;
  let requirementsHash: string;
  try {
    requirementsHash = paymentRequirementsHash(input.payment.paymentRequirements);
  } catch {
    return reject("The x402 payment requirements are invalid", "INVALID_A2A_INPUT");
  }
  if (
    submission.task_id !== task.id ||
    submission.context_id !== task.contextId ||
    submission.resource !== input.payment.resource ||
    submission.payment_requirements_hash !== requirementsHash
  ) {
    return reject(
      "The submitted payment is not bound to this A2A task and x402 challenge",
      "PAYMENT_BINDING_MISMATCH",
    );
  }

  const binding = A2AActionBindingSchema.parse({
    version: "inntris-a2a-binding-v1",
    task_id: task.id,
    context_id: task.contextId,
    payment_submission_id: submission.submission_id,
    payment_requirements_hash: requirementsHash,
    resource: input.payment.resource,
    required_finality: finalityResult.data,
  });
  return {
    task,
    paymentSubmission: submission,
    payment: {
      ...input.payment,
      extensions: {
        ...input.payment.extensions,
        [A2A_ACTION_EXTENSION_KEY]: binding,
      },
    },
    binding,
    requiredFinality: finalityResult.data,
  };
}

function verifySettlementBinding(settlement: A2ASettlementObservation, input: PreparedInput): void {
  if (
    settlement.task_id !== input.task.id ||
    settlement.context_id !== input.task.contextId ||
    settlement.payment_submission_id !== input.paymentSubmission.submission_id ||
    settlement.payment_requirements_hash !== input.paymentSubmission.payment_requirements_hash ||
    settlement.resource !== input.payment.resource
  ) {
    reject(
      "Settlement evidence is bound to a different task, submission, or resource",
      "SETTLEMENT_BINDING_MISMATCH",
    );
  }
  if (
    input.paymentSubmission.settlement_ref !== null &&
    settlement.settlement_ref !== input.paymentSubmission.settlement_ref
  ) {
    reject(
      "Settlement evidence is bound to a different settlement reference",
      "SETTLEMENT_BINDING_MISMATCH",
    );
  }
  if (Date.parse(settlement.observed_at) < Date.parse(input.paymentSubmission.submitted_at)) {
    reject("Settlement evidence predates the submitted payment", "SETTLEMENT_BINDING_MISMATCH");
  }
}

function requireFinalSettlement(
  settlement: A2ASettlementObservation,
  requiredFinality: string,
): void {
  if (settlement.state === "UNKNOWN" || settlement.finality === "UNKNOWN") {
    reject("Settlement state is unknown; delegate execution is paused", "SETTLEMENT_UNKNOWN");
  }
  if (settlement.state === "FAILED") {
    reject("Settlement failed; delegate execution is blocked", "SETTLEMENT_FAILED");
  }
  if (
    settlement.state !== "SETTLED" ||
    settlement.settlement_ref === null ||
    settlement.finality !== requiredFinality
  ) {
    reject(
      "Payment submission is not proof of the required settlement finality",
      "SETTLEMENT_NOT_FINAL",
    );
  }
}

export class InntrisA2ASettlementGate {
  readonly #clock: Clock;
  readonly #executionStore: A2AExecutionStore;
  readonly #requiredFinality: string;

  constructor(readonly options: InntrisA2ASettlementGateOptions) {
    this.#clock = options.clock ?? { now: () => new Date() };
    this.#executionStore = options.executionStore ?? new InMemoryA2AExecutionStore();
    this.#requiredFinality = A2AFinalityRequirementSchema.parse(options.requiredFinality);
  }

  async process<T>(
    input: A2ASettlementGateInput,
    executeDelegate: A2ADelegate<T>,
  ): Promise<A2ASettlementGateResult<T>> {
    const prepared = prepareInput(input, this.#requiredFinality);
    let decision: InntrisDecisionV1;
    try {
      decision = await this.options.guard.authorise(prepared.payment);
    } catch (error) {
      return reject(
        "Inntris decision evaluation or verification failed closed",
        "DECISION_INVALID",
        error instanceof Error ? error.name : undefined,
      );
    }
    if (decision.verdict !== "ALLOW") {
      return reject("Inntris did not authorise the paid A2A task", "DECISION_NOT_ALLOW");
    }

    const settlementIdempotencyKey = `a2a-settlement:${hashCanonical(prepared.binding).slice(7)}`;
    let rawSettlement: unknown;
    try {
      rawSettlement =
        prepared.paymentSubmission.settlement_ref === null
          ? await this.options.settlementProvider.settle({
              task: prepared.task,
              paymentSubmission: prepared.paymentSubmission,
              payment: prepared.payment,
              decision,
              idempotencyKey: settlementIdempotencyKey,
              requiredFinality: prepared.requiredFinality,
            })
          : await this.options.settlementProvider.confirm({
              task: prepared.task,
              paymentSubmission: prepared.paymentSubmission,
              payment: prepared.payment,
              decision,
              idempotencyKey: settlementIdempotencyKey,
              requiredFinality: prepared.requiredFinality,
              settlementRef: prepared.paymentSubmission.settlement_ref,
            });
    } catch (error) {
      return reject(
        "Settlement provider failed; delegate execution is paused",
        "SETTLEMENT_UNKNOWN",
        error instanceof Error ? error.name : undefined,
      );
    }

    const settlementResult = A2ASettlementObservationSchema.safeParse(rawSettlement);
    if (!settlementResult.success) {
      return reject(
        "Settlement provider returned malformed evidence",
        "SETTLEMENT_UNKNOWN",
        "INVALID_SETTLEMENT_SCHEMA",
      );
    }
    const settlement = settlementResult.data;
    verifySettlementBinding(settlement, prepared);
    requireFinalSettlement(settlement, prepared.requiredFinality);

    const postSettlementVerification = await this.options.guard.verifyBeforeSettlement(
      prepared.payment,
      decision,
    );
    if (!postSettlementVerification.valid || postSettlementVerification.verdict !== "ALLOW") {
      return reject(
        "The Inntris decision is no longer valid after settlement confirmation",
        "DECISION_INVALID",
        postSettlementVerification.reason_codes.join(","),
      );
    }

    const executionRef = `a2a-execution:${hashCanonical({
      version: "inntris-a2a-execution-ref-v1",
      task_id: prepared.task.id,
      context_id: prepared.task.contextId,
      payment_submission_id: prepared.paymentSubmission.submission_id,
      settlement_ref: settlement.settlement_ref,
      action_hash: decision.action_hash,
    }).slice(7)}`;
    const consumption = await this.options.guard.consumeBeforeExecution(decision, executionRef);
    if (!consumption.success) {
      return reject(
        "Inntris decision consumption failed; delegate execution is blocked",
        "DECISION_CONSUMPTION_FAILED",
        consumption.reason_code,
      );
    }

    const executionBindingHash = hashCanonical({
      version: "inntris-a2a-execution-binding-v1",
      task_id: prepared.task.id,
      context_id: prepared.task.contextId,
      payment_submission_id: prepared.paymentSubmission.submission_id,
      resource: prepared.payment.resource,
      settlement_ref: settlement.settlement_ref,
      action_hash: decision.action_hash,
    });
    let claim;
    try {
      claim = await this.#executionStore.claim({
        executionRef,
        bindingHash: executionBindingHash,
      });
    } catch (error) {
      return reject(
        "Delegate execution state is unavailable; automatic execution is paused",
        "DELEGATE_EXECUTION_STORE_UNAVAILABLE",
        error instanceof Error ? error.name : undefined,
      );
    }
    if (claim.status === "conflict") {
      return reject(
        "Execution reference is already bound to different A2A evidence",
        "DELEGATE_EXECUTION_CONFLICT",
      );
    }
    if (claim.status === "in_progress") {
      return reject(
        "Delegate execution has an unresolved prior attempt; automatic retry is paused",
        "DELEGATE_EXECUTION_IN_PROGRESS",
      );
    }
    if (claim.status === "completed") {
      return {
        decision,
        settlement,
        execution_ref: executionRef,
        receipt: claim.receipt,
        result: claim.result as T,
        replayed: true,
      };
    }

    let result: T;
    try {
      result = await executeDelegate({
        task: prepared.task,
        decision,
        settlement,
        executionRef,
      });
    } catch (error) {
      return reject(
        "Delegate execution failed after it was claimed; automatic retry is paused",
        "DELEGATE_EXECUTION_FAILED",
        error instanceof Error ? error.name : undefined,
      );
    }

    let receipt;
    try {
      receipt = await createA2AActionReceipt({
        task: prepared.task,
        resource: prepared.payment.resource,
        paymentSubmissionId: prepared.paymentSubmission.submission_id,
        decision,
        settlement,
        executionRef,
        delegateResult: result,
        signer: this.options.receiptSigner,
        executedAt: this.#clock.now(),
      });
    } catch (error) {
      return reject(
        "Delegate completed but its action receipt could not be signed; reconciliation is required",
        "RECEIPT_SIGNING_FAILED",
        error instanceof Error ? error.name : undefined,
      );
    }
    try {
      await this.#executionStore.complete({
        executionRef,
        bindingHash: executionBindingHash,
        receipt,
        result,
      });
    } catch (error) {
      return reject(
        "Delegate completed but execution state could not be finalised; reconciliation is required",
        "DELEGATE_EXECUTION_STORE_UNAVAILABLE",
        error instanceof Error ? error.name : undefined,
      );
    }
    return {
      decision,
      settlement,
      execution_ref: executionRef,
      receipt,
      result,
      replayed: false,
    };
  }
}
