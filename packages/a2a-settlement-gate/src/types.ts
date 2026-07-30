import type { Task } from "@a2a-js/sdk";
import {
  Base64UrlSchema,
  HashSchema,
  IdentifierSchema,
  IsoTimestampSchema,
  type InntrisDecisionV1,
} from "@inntris/decision-core";
import type { X402SettlementInput } from "@inntris/x402-adapter";
import { z } from "zod";

export const A2A_ACTION_EXTENSION_KEY = "inntris_a2a";

export const A2AFinalityRequirementSchema = z
  .string()
  .min(1)
  .max(128)
  .refine(
    (value) => !["UNKNOWN", "PENDING", "PAYMENT_SUBMITTED"].includes(value),
    "Required finality must identify a conclusive settlement state",
  );

export const A2APaymentSubmissionSchema = z
  .object({
    version: z.literal("inntris-a2a-payment-submission-v1"),
    state: z.literal("PAYMENT_SUBMITTED"),
    submission_id: IdentifierSchema,
    task_id: IdentifierSchema,
    context_id: IdentifierSchema,
    resource: z.url(),
    payment_requirements_hash: HashSchema,
    submitted_at: IsoTimestampSchema,
    settlement_ref: z.string().min(1).max(512).nullable(),
  })
  .strict();

export const A2AActionBindingSchema = z
  .object({
    version: z.literal("inntris-a2a-binding-v1"),
    task_id: IdentifierSchema,
    context_id: IdentifierSchema,
    payment_submission_id: IdentifierSchema,
    payment_requirements_hash: HashSchema,
    resource: z.url(),
    required_finality: A2AFinalityRequirementSchema,
  })
  .strict();

export const A2ASettlementObservationSchema = z
  .object({
    version: z.literal("inntris-a2a-settlement-observation-v1"),
    state: z.enum(["PAYMENT_SUBMITTED", "SETTLED", "FAILED", "UNKNOWN"]),
    task_id: IdentifierSchema,
    context_id: IdentifierSchema,
    payment_submission_id: IdentifierSchema,
    payment_requirements_hash: HashSchema,
    resource: z.url(),
    settlement_ref: z.string().min(1).max(512).nullable(),
    finality: z.string().min(1).max(128).nullable(),
    observed_at: IsoTimestampSchema,
    evidence: z.record(z.string(), z.unknown()),
  })
  .strict()
  .superRefine((observation, context) => {
    if (
      observation.state === "SETTLED" &&
      (observation.settlement_ref === null || observation.finality === null)
    ) {
      context.addIssue({
        code: "custom",
        message: "A settled observation requires settlement_ref and finality",
      });
    }
  });

export const A2AActionReceiptSchema = z
  .object({
    version: z.literal("inntris-a2a-action-receipt-v1"),
    receipt_id: IdentifierSchema,
    receipt_fingerprint: HashSchema,
    task_id: IdentifierSchema,
    context_id: IdentifierSchema,
    resource: z.url(),
    payment_submission_id: IdentifierSchema,
    decision_id: IdentifierSchema,
    decision_fingerprint: HashSchema,
    action_hash: HashSchema,
    settlement_ref: z.string().min(1).max(512),
    settlement_evidence_hash: HashSchema,
    execution_ref: z.string().min(1).max(512),
    delegate_result_hash: HashSchema,
    executed_at: IsoTimestampSchema,
    signing: z
      .object({
        alg: z.literal("Ed25519"),
        key_id: IdentifierSchema,
        signature: Base64UrlSchema,
      })
      .strict(),
  })
  .strict();

export type A2APaymentSubmission = z.infer<typeof A2APaymentSubmissionSchema>;
export type A2AActionBinding = z.infer<typeof A2AActionBindingSchema>;
export type A2ASettlementObservation = z.infer<typeof A2ASettlementObservationSchema>;
export type A2AActionReceipt = z.infer<typeof A2AActionReceiptSchema>;
export type A2ATaskReference = Pick<Task, "id" | "contextId">;

export interface A2ASettlementGateInput {
  task: A2ATaskReference;
  paymentSubmission: A2APaymentSubmission;
  payment: X402SettlementInput;
}

export interface A2ASettlementRequest {
  task: A2ATaskReference;
  paymentSubmission: A2APaymentSubmission;
  payment: X402SettlementInput;
  decision: InntrisDecisionV1;
  idempotencyKey: string;
  requiredFinality: string;
}

export interface A2ASettlementConfirmationRequest extends A2ASettlementRequest {
  settlementRef: string;
}

export interface A2ASettlementProvider {
  settle(input: A2ASettlementRequest): Promise<unknown>;
  confirm(input: A2ASettlementConfirmationRequest): Promise<unknown>;
}

export interface A2ADelegateInput {
  task: A2ATaskReference;
  decision: InntrisDecisionV1;
  settlement: A2ASettlementObservation;
  executionRef: string;
}

export type A2ADelegate<T> = (input: A2ADelegateInput) => Promise<T>;

export interface A2ASettlementGateResult<T> {
  decision: InntrisDecisionV1;
  settlement: A2ASettlementObservation;
  execution_ref: string;
  receipt: A2AActionReceipt;
  result: T;
  replayed: boolean;
}

export type A2AGateReasonCode =
  | "INVALID_A2A_INPUT"
  | "PAYMENT_BINDING_MISMATCH"
  | "DECISION_INVALID"
  | "DECISION_NOT_ALLOW"
  | "SETTLEMENT_FAILED"
  | "SETTLEMENT_NOT_FINAL"
  | "SETTLEMENT_UNKNOWN"
  | "SETTLEMENT_BINDING_MISMATCH"
  | "DECISION_CONSUMPTION_FAILED"
  | "DELEGATE_EXECUTION_IN_PROGRESS"
  | "DELEGATE_EXECUTION_CONFLICT"
  | "DELEGATE_EXECUTION_STORE_UNAVAILABLE"
  | "DELEGATE_EXECUTION_FAILED"
  | "RECEIPT_SIGNING_FAILED";
