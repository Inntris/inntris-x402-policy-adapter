import { HashSchema, IdentifierSchema, RailSchema } from "@inntris/decision-core";
import { z } from "zod";

export const ExecutionOperationKindSchema = z.enum([
  "x402_settlement",
  "a2a_settlement",
  "a2a_delegate",
  "ap2_delegate",
  "evm_broadcast",
  "mtp_consumption",
]);

export const ExecutionOperationStatusSchema = z.enum([
  "prepared",
  "in_progress",
  "succeeded",
  "failed_final",
  "outcome_unknown",
]);

export const PrepareExecutionOperationSchema = z
  .object({
    rail: RailSchema,
    operationKind: ExecutionOperationKindSchema,
    decisionId: IdentifierSchema,
    actionHash: HashSchema,
    executionRef: z.string().min(1).max(512),
    bindingHash: HashSchema,
    preparedAt: z.date(),
  })
  .strict();

export const ExecutionOperationRecordSchema = z
  .object({
    version: z.literal("inntris-execution-operation-v1"),
    operationId: HashSchema,
    rail: RailSchema,
    operationKind: ExecutionOperationKindSchema,
    decisionId: IdentifierSchema,
    actionHash: HashSchema,
    executionRef: z.string().min(1).max(512),
    bindingHash: HashSchema,
    status: ExecutionOperationStatusSchema,
    attemptCount: z.number().int().nonnegative(),
    preparedAt: z.iso.datetime({ offset: true }),
    startedAt: z.iso.datetime({ offset: true }).nullable(),
    updatedAt: z.iso.datetime({ offset: true }),
    resolvedAt: z.iso.datetime({ offset: true }).nullable(),
    outcomeReference: z.string().min(1).max(512).nullable(),
    lastErrorCode: z.string().min(1).max(128).nullable(),
    resolvedBy: IdentifierSchema.nullable(),
    resolutionNote: z.string().min(1).max(1_024).nullable(),
  })
  .strict();

export const StartExecutionOperationSchema = z
  .object({
    operationId: HashSchema,
    bindingHash: HashSchema,
    startedAt: z.date(),
  })
  .strict();

export const MarkExecutionSucceededSchema = z
  .object({
    operationId: HashSchema,
    bindingHash: HashSchema,
    outcomeReference: z.string().min(1).max(512),
    resolvedAt: z.date(),
  })
  .strict();

export const MarkExecutionFailedFinalSchema = z
  .object({
    operationId: HashSchema,
    bindingHash: HashSchema,
    errorCode: z.string().min(1).max(128),
    resolvedAt: z.date(),
  })
  .strict();

export const MarkExecutionOutcomeUnknownSchema = z
  .object({
    operationId: HashSchema,
    bindingHash: HashSchema,
    errorCode: z.string().min(1).max(128),
    observedAt: z.date(),
  })
  .strict();

export const ResolveExecutionOperationSchema = z
  .object({
    operationId: HashSchema,
    bindingHash: HashSchema,
    outcome: z.enum(["succeeded", "failed_final"]),
    outcomeReference: z.string().min(1).max(512),
    errorCode: z.string().min(1).max(128).optional(),
    resolvedBy: IdentifierSchema,
    resolutionNote: z.string().min(1).max(1_024),
    resolvedAt: z.date(),
  })
  .strict()
  .superRefine((value, context) => {
    if (value.outcome === "failed_final" && value.errorCode === undefined) {
      context.addIssue({
        code: "custom",
        path: ["errorCode"],
        message: "A final failure resolution requires an error code",
      });
    }
  });

export const ListUnresolvedExecutionOperationsSchema = z
  .object({
    updatedBefore: z.date().optional(),
    limit: z.number().int().min(1).max(500).optional(),
  })
  .strict();

export type ExecutionOperationKind = z.infer<typeof ExecutionOperationKindSchema>;
export type ExecutionOperationStatus = z.infer<typeof ExecutionOperationStatusSchema>;
export type PrepareExecutionOperation = z.infer<typeof PrepareExecutionOperationSchema>;
export type ExecutionOperationRecord = z.infer<typeof ExecutionOperationRecordSchema>;
export type StartExecutionOperation = z.infer<typeof StartExecutionOperationSchema>;
export type MarkExecutionSucceeded = z.infer<typeof MarkExecutionSucceededSchema>;
export type MarkExecutionFailedFinal = z.infer<typeof MarkExecutionFailedFinalSchema>;
export type MarkExecutionOutcomeUnknown = z.infer<typeof MarkExecutionOutcomeUnknownSchema>;
export type ResolveExecutionOperation = z.infer<typeof ResolveExecutionOperationSchema>;
export type ListUnresolvedExecutionOperations = z.infer<
  typeof ListUnresolvedExecutionOperationsSchema
>;

export type ExecutionStartResult =
  | { status: "claimed"; operation: ExecutionOperationRecord }
  | { status: "in_progress"; operation: ExecutionOperationRecord }
  | { status: "succeeded"; operation: ExecutionOperationRecord }
  | { status: "failed_final"; operation: ExecutionOperationRecord }
  | { status: "outcome_unknown"; operation: ExecutionOperationRecord }
  | { status: "conflict" }
  | { status: "missing" };

export interface ExecutionReconciliationStore {
  prepare(input: PrepareExecutionOperation): Promise<ExecutionOperationRecord>;
  start(input: StartExecutionOperation): Promise<ExecutionStartResult>;
  markSucceeded(input: MarkExecutionSucceeded): Promise<ExecutionOperationRecord>;
  markFailedFinal(input: MarkExecutionFailedFinal): Promise<ExecutionOperationRecord>;
  markOutcomeUnknown(input: MarkExecutionOutcomeUnknown): Promise<ExecutionOperationRecord>;
  resolve(input: ResolveExecutionOperation): Promise<ExecutionOperationRecord>;
  get(operationId: string): Promise<ExecutionOperationRecord | undefined>;
  listUnresolved(input?: ListUnresolvedExecutionOperations): Promise<ExecutionOperationRecord[]>;
}

export class ExecutionReconciliationError extends Error {
  override readonly name = "ExecutionReconciliationError";
}
