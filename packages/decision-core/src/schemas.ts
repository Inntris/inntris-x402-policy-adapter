import { z } from "zod";

export const HashSchema = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
export const Base64UrlSchema = z
  .string()
  .min(1)
  .regex(/^[A-Za-z0-9_-]+$/u);
export const IdentifierSchema = z.string().min(1).max(128);
export const IsoTimestampSchema = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u)
  .refine((value) => !Number.isNaN(Date.parse(value)), "Invalid UTC timestamp");

/**
 * Inntris monetary values use a unique decimal representation:
 * at least two fractional digits, no leading zeroes and no redundant
 * trailing zeroes beyond the second fractional digit.
 */
export const CanonicalAmountSchema = z
  .string()
  .regex(/^(0|[1-9]\d*)\.\d{2,18}$/u)
  .refine((value) => {
    const fraction = value.split(".")[1];
    return fraction !== undefined && (fraction.length === 2 || !fraction.endsWith("0"));
  }, "Amount contains redundant trailing zeroes");

export const TransactionSchema = z
  .object({
    amount: CanonicalAmountSchema,
    asset: z.string().min(1).max(128),
    network: z.string().min(1).max(128),
    payee: z.string().min(1).max(512),
    purpose: z.string().min(1).max(128),
  })
  .strict();

export const X402ProtocolReferenceSchema = z
  .object({
    type: z.literal("x402"),
    resource: z.url(),
    scheme: z.string().min(1).max(64),
    payment_requirements_hash: HashSchema,
    payment_payload_hash: HashSchema.nullable(),
  })
  .strict();

export const AP2ProtocolReferenceSchema = z
  .object({
    type: z.literal("ap2"),
    protocol_version: z.literal("0.2"),
    resource: z.url(),
    mode: z.literal("autonomous"),
    intent_verification_hash: HashSchema,
    checkout_mandate_hash: HashSchema,
    payment_mandate_hash: HashSchema,
    checkout_hash: Base64UrlSchema,
    transaction_id: Base64UrlSchema,
  })
  .strict();

export const EVMProtocolReferenceSchema = z
  .object({
    type: z.literal("evm"),
    resource: z.url(),
    transaction_type: z.enum(["eip1559", "legacy"]),
    chain_id: z.string().regex(/^[1-9]\d*$/u),
    from: z.string().regex(/^0x[0-9a-f]{40}$/u),
    to: z.string().regex(/^0x[0-9a-f]{40}$/u),
    value_wei: z.string().regex(/^(0|[1-9]\d*)$/u),
    nonce: z.string().regex(/^(0|[1-9]\d*)$/u),
    unsigned_transaction_hash: HashSchema,
    data_hash: HashSchema,
  })
  .strict();

export const CardProtocolReferenceSchema = z
  .object({
    type: z.literal("card"),
    resource: z.url(),
    authorisation_request_id: IdentifierSchema,
    merchant_id: IdentifierSchema,
    card_network: z.string().min(1).max(64),
    credential_reference_hash: HashSchema,
    authorisation_request_hash: HashSchema,
  })
  .strict();

export const MCPProtocolReferenceSchema = z
  .object({
    type: z.literal("mcp"),
    resource: z.url(),
    server_id: IdentifierSchema,
    tool_name: IdentifierSchema,
    tool_call_id: IdentifierSchema,
    tool_arguments_hash: HashSchema,
    payment_reference_hash: HashSchema,
  })
  .strict();

export const ProtocolReferenceSchema = z.discriminatedUnion("type", [
  X402ProtocolReferenceSchema,
  AP2ProtocolReferenceSchema,
  EVMProtocolReferenceSchema,
  CardProtocolReferenceSchema,
  MCPProtocolReferenceSchema,
]);

export const RailSchema = z.enum(["x402", "ap2", "evm", "card", "mcp"]);

const ActionBaseShape = {
  version: z.literal("inntris-action-v1"),
  principal_id: IdentifierSchema,
  agent_id: IdentifierSchema,
  action_type: z.literal("financial_transaction"),
  transaction: TransactionSchema,
  extensions: z.record(z.string(), z.unknown()).optional(),
};

export const InntrisActionV1Schema = z.discriminatedUnion("rail", [
  z
    .object({
      ...ActionBaseShape,
      rail: z.literal("x402"),
      protocol_reference: X402ProtocolReferenceSchema,
    })
    .strict(),
  z
    .object({
      ...ActionBaseShape,
      rail: z.literal("ap2"),
      protocol_reference: AP2ProtocolReferenceSchema,
    })
    .strict(),
  z
    .object({
      ...ActionBaseShape,
      rail: z.literal("evm"),
      protocol_reference: EVMProtocolReferenceSchema,
    })
    .strict(),
  z
    .object({
      ...ActionBaseShape,
      rail: z.literal("card"),
      protocol_reference: CardProtocolReferenceSchema,
    })
    .strict(),
  z
    .object({
      ...ActionBaseShape,
      rail: z.literal("mcp"),
      protocol_reference: MCPProtocolReferenceSchema,
    })
    .strict(),
]);

export const VerdictSchema = z.enum(["ALLOW", "BLOCK", "REQUIRE_APPROVAL"]);

export const ReasonCodeSchema = z.enum([
  "MERCHANT_ALLOWED",
  "WITHIN_TRANSACTION_LIMIT",
  "WITHIN_DAILY_LIMIT",
  "DEFAULT_DENY",
  "NETWORK_NOT_ALLOWED",
  "ASSET_NOT_ALLOWED",
  "PAYEE_NOT_ALLOWED",
  "RESOURCE_NOT_ALLOWED",
  "PURPOSE_NOT_ALLOWED",
  "AMOUNT_EXCEEDS_TRANSACTION_LIMIT",
  "DAILY_LIMIT_EXCEEDED",
  "OUTSIDE_ALLOWED_TIME",
  "HUMAN_APPROVAL_REQUIRED",
  "HUMAN_APPROVAL_GRANTED",
  "HUMAN_APPROVAL_REFUSED",
  "APPROVAL_NOT_PENDING",
  "APPROVAL_ALREADY_RESOLVED",
  "POLICY_EXPIRED",
  "POLICY_VERSION_MISMATCH",
  "ACTION_HASH_MISMATCH",
  "PAYMENT_REQUIREMENTS_MISMATCH",
  "DECISION_BINDING_MISMATCH",
  "DECISION_EXPIRED",
  "INVALID_DECISION_SCHEMA",
  "FINGERPRINT_MISMATCH",
  "INVALID_SIGNATURE",
  "UNKNOWN_SIGNING_KEY",
  "NONCE_ALREADY_CONSUMED",
  "DECISION_NOT_ALLOW",
  "DECISION_SERVICE_UNAVAILABLE",
]);

export const ApprovalSchema = z
  .object({
    mode: z.enum(["policy_engine", "human"]),
    approval_reference: z.string().min(1).max(256).nullable(),
    approver_ids: z.array(IdentifierSchema).max(32),
  })
  .strict();

export const DecisionSigningSchema = z
  .object({
    alg: z.literal("Ed25519"),
    key_id: IdentifierSchema,
    signature: Base64UrlSchema,
  })
  .strict();

const DecisionBaseShape = {
  version: z.literal("inntris-decision-v1"),
  decision_id: IdentifierSchema,
  decision_fingerprint: HashSchema,
  verdict: VerdictSchema,
  principal_id: IdentifierSchema,
  agent_id: IdentifierSchema,
  action_type: z.literal("financial_transaction"),
  action_hash: HashSchema,
  transaction: TransactionSchema,
  policy: z
    .object({
      policy_hash: HashSchema,
      policy_version: z.string().min(1).max(64),
    })
    .strict(),
  approval: ApprovalSchema,
  reason_codes: z.array(ReasonCodeSchema).min(1),
  issued_at: IsoTimestampSchema,
  expires_at: IsoTimestampSchema,
  nonce: Base64UrlSchema,
  supersedes_decision_id: IdentifierSchema.nullable(),
  signing: DecisionSigningSchema,
};

export const InntrisDecisionV1Schema = z
  .discriminatedUnion("rail", [
    z
      .object({
        ...DecisionBaseShape,
        rail: z.literal("x402"),
        protocol_reference: X402ProtocolReferenceSchema,
      })
      .strict(),
    z
      .object({
        ...DecisionBaseShape,
        rail: z.literal("ap2"),
        protocol_reference: AP2ProtocolReferenceSchema,
      })
      .strict(),
    z
      .object({
        ...DecisionBaseShape,
        rail: z.literal("evm"),
        protocol_reference: EVMProtocolReferenceSchema,
      })
      .strict(),
    z
      .object({
        ...DecisionBaseShape,
        rail: z.literal("card"),
        protocol_reference: CardProtocolReferenceSchema,
      })
      .strict(),
    z
      .object({
        ...DecisionBaseShape,
        rail: z.literal("mcp"),
        protocol_reference: MCPProtocolReferenceSchema,
      })
      .strict(),
  ])
  .superRefine((decision, context) => {
    if (Date.parse(decision.expires_at) <= Date.parse(decision.issued_at)) {
      context.addIssue({
        code: "custom",
        message: "expires_at must be later than issued_at",
        path: ["expires_at"],
      });
    }
    if (new Set(decision.reason_codes).size !== decision.reason_codes.length) {
      context.addIssue({
        code: "custom",
        message: "reason_codes must not contain duplicates",
        path: ["reason_codes"],
      });
    }
  });

export const KeyRegistryEntrySchema = z
  .object({
    key_id: IdentifierSchema,
    alg: z.literal("Ed25519"),
    public_key: Base64UrlSchema,
    fingerprint: HashSchema,
    status: z.enum(["active", "retired", "revoked"]),
    not_before: IsoTimestampSchema,
    not_after: IsoTimestampSchema.nullable(),
  })
  .strict();

export const KeyRegistrySchema = z
  .object({
    version: z.literal("inntris-key-registry-v1"),
    keys: z.array(KeyRegistryEntrySchema).min(1),
  })
  .strict()
  .superRefine((registry, context) => {
    const ids = registry.keys.map((key) => key.key_id);
    if (new Set(ids).size !== ids.length) {
      context.addIssue({
        code: "custom",
        message: "key_id values must be unique",
        path: ["keys"],
      });
    }
  });

export type InntrisActionV1 = z.infer<typeof InntrisActionV1Schema>;
export type InntrisDecisionV1 = z.infer<typeof InntrisDecisionV1Schema>;
export type Transaction = z.infer<typeof TransactionSchema>;
export type ProtocolReference = z.infer<typeof ProtocolReferenceSchema>;
export type Rail = z.infer<typeof RailSchema>;
export type Verdict = z.infer<typeof VerdictSchema>;
export type ReasonCode = z.infer<typeof ReasonCodeSchema>;
export type Approval = z.infer<typeof ApprovalSchema>;
export type KeyRegistry = z.infer<typeof KeyRegistrySchema>;
export type KeyRegistryEntry = z.infer<typeof KeyRegistryEntrySchema>;
