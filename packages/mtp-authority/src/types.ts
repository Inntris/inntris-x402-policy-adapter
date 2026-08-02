import { z } from "zod";

const RawSha256Schema = z.string().regex(/^[0-9a-f]{64}$/u);

export const MtpSignedVerifyRequestSchema = z
  .object({
    agent_id: z.uuid(),
    action_type: z.literal("financial_transaction"),
    payload: z.record(z.string(), z.unknown()),
    nonce: z.string().min(1).max(64),
    timestamp: z.iso.datetime({ offset: true }),
    signature: z.string().min(1),
    sig_version: z.literal(3),
    policy_hash: RawSha256Schema.optional(),
  })
  .strict();

export const MtpApprovedResponseSchema = z
  .object({
    verdict: z.literal("approved"),
    approval_token: z.string().min(1),
    trust_score: z.number().int().min(0).max(100),
    audit_id: z.uuid(),
    timestamp: z.iso.datetime({ offset: true }),
    limits_remaining: z.record(z.string(), z.unknown()).nullable().optional(),
  })
  .strip();

export const MtpTokenResponseSchema = z
  .object({
    valid: z.boolean(),
    reason: z.string().nullable().optional(),
    verdict: z.string().nullable().optional(),
    agent_id: z.string().nullable().optional(),
    action_hash: RawSha256Schema.nullable().optional(),
    expires_at: z.string().nullable().optional(),
    action_hash_matches: z.boolean().nullable().optional(),
    consumption_audit_id: z.string().nullable().optional(),
    consumption_status: z.enum(["consumed", "idempotent"]).nullable().optional(),
    execution_ref: z.string().nullable().optional(),
    sandbox: z.boolean().nullable().optional(),
  })
  .strip();

export type MtpSignedVerifyRequest = z.infer<typeof MtpSignedVerifyRequestSchema>;

export interface MtpAuthorizationRecord {
  decisionId: string;
  actionHash: string;
  request: MtpSignedVerifyRequest;
  mtpActionHash: string;
  approvalToken: string;
  authorizationAuditId: string;
  authorizedAt: string;
  executionRef?: string | undefined;
  consumptionAuditId?: string | undefined;
  consumptionStatus?: "consumed" | "idempotent" | undefined;
  completedAt?: string | undefined;
}

export interface MtpConsumptionReceipt {
  executionRef: string;
  consumptionAuditId: string;
  status: "consumed" | "idempotent";
}

export type MtpExecutionClaim = "claimed" | "idempotent" | "conflict" | "missing";

export interface MtpAuthorityStateStore {
  saveAuthorization(record: MtpAuthorizationRecord): Promise<void>;
  getAuthorization(decisionId: string): Promise<MtpAuthorizationRecord | undefined>;
  claimExecution(
    decisionId: string,
    actionHash: string,
    executionRef: string,
  ): Promise<MtpExecutionClaim>;
  markMtpConsumed(
    decisionId: string,
    executionRef: string,
    receipt: MtpConsumptionReceipt,
  ): Promise<void>;
  markComplete(decisionId: string, executionRef: string, completedAt: string): Promise<void>;
}
