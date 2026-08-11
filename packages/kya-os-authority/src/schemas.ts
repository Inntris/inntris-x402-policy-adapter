import { HashSchema, InntrisActionV1Schema, IsoTimestampSchema } from "@inntris/decision-core";
import { z } from "zod";

export const KYA_AUTHORITY_EXTENSION_KEY = "org.inntris/kya-os";
export const KYA_PROTOCOL_VERSION = "1.0.0";
export const KYA_REFERENCE_PACKAGE = "@kya-os/mcp";
export const KYA_REFERENCE_PACKAGE_VERSION = "1.12.0";

export const KyaProfileSchema = z.enum(["entity-card-v1", "legacy-v1"]);
export const KyaDidMethodSchema = z.enum(["did:key", "did:web"]);
export const KyaProofAssuranceSchema = z.enum(["L3-minus", "L3"]);

export const KyaAmountSchema = z
  .string()
  .regex(/^(0|[1-9]\d*)\.\d{2,6}$/u)
  .refine((value) => {
    const fraction = value.split(".")[1];
    return fraction !== undefined && (fraction.length === 2 || !fraction.endsWith("0"));
  }, "KYA amount is not canonical");

export const KyaToolRequestSchema = z
  .object({
    method: z.string().min(1).max(128),
    params: z.unknown().optional(),
  })
  .strict();

export const KyaPaymentRequestV1Schema = z
  .object({
    method: z.literal("tools/call"),
    params: z
      .object({
        name: z.literal("payments.transfer"),
        arguments: z
          .object({
            to: z.string().min(1).max(512),
            amount: KyaAmountSchema,
            currency: z.string().min(1).max(128),
            resource: z.string().min(1).max(1_024),
          })
          .strict(),
      })
      .strict(),
  })
  .strict();

export const KyaEntityCardAuthorityPresentationSchema = z
  .object({
    profile: z.literal("entity-card-v1"),
    request: KyaToolRequestSchema,
    request_proof: z.unknown(),
    delegation_chain: z.array(z.unknown()).min(1).max(10),
    entity_card: z.unknown().optional(),
    token_cnf_jkt: z.string().min(1).optional(),
  })
  .strict();

export const KyaLegacyAuthorityPresentationSchema = z
  .object({
    profile: z.literal("legacy-v1"),
    request: KyaToolRequestSchema,
    credential: z.union([z.string().min(1), z.record(z.string(), z.unknown())]),
    audience: z.string().min(1),
    proof: z.unknown().optional(),
  })
  .strict();

export const KyaAuthorityPresentationSchema = z.discriminatedUnion("profile", [
  KyaEntityCardAuthorityPresentationSchema,
  KyaLegacyAuthorityPresentationSchema,
]);

const ResourceBindingSchema = z
  .object({
    inntris_resource: z.url(),
    kya_invocation_target: z.string().min(1).max(1_024),
  })
  .strict();

const CurrencyBindingSchema = z
  .object({
    inntris_asset: z.string().min(1).max(128),
    kya_currency: z.string().min(1).max(128),
  })
  .strict();

const PayeeBindingSchema = z
  .object({
    inntris_payee: z.string().min(1).max(512),
    kya_payee: z.string().min(1).max(512),
  })
  .strict();

export const KyaAuthorityPolicyV1Schema = z
  .object({
    version: z.literal(1),
    policy_id: z.string().min(1).max(128),
    policy_version: z.string().min(1).max(64),
    mode: z.enum(["required", "optional"]),
    profiles: z.array(KyaProfileSchema).min(1).max(2),
    expected_audiences: z.array(z.string().min(1)).min(1),
    accepted_did_methods: z.array(KyaDidMethodSchema).min(1).max(2),
    responsible_parties: z.array(z.string().min(1)).min(1),
    allowed_actions: z.array(z.literal("payments.transfer")).min(1),
    min_proof_assurance: KyaProofAssuranceSchema,
    require_fresh_revocation: z.boolean(),
    require_max_amount: z.boolean(),
    max_delegation_depth: z.number().int().min(1).max(10),
    principal_source: z.enum(["responsible_party", "card_principal"]),
    resource_bindings: z.array(ResourceBindingSchema).min(1),
    currency_bindings: z.array(CurrencyBindingSchema).min(1),
    payee_bindings: z.array(PayeeBindingSchema).optional(),
  })
  .strict()
  .superRefine((policy, context) => {
    const unique = (values: string[], path: string): void => {
      if (new Set(values).size !== values.length) {
        context.addIssue({ code: "custom", message: `${path} must be unique`, path: [path] });
      }
    };
    unique(policy.profiles, "profiles");
    unique(policy.expected_audiences, "expected_audiences");
    unique(policy.accepted_did_methods, "accepted_did_methods");
    unique(policy.responsible_parties, "responsible_parties");
    unique(
      policy.resource_bindings.map((binding) => binding.inntris_resource),
      "resource_bindings",
    );
    unique(
      policy.currency_bindings.map((binding) => binding.inntris_asset),
      "currency_bindings",
    );
  });

const BindingReferenceImplementationSchema = z
  .object({
    package: z.literal(KYA_REFERENCE_PACKAGE),
    version: z.literal(KYA_REFERENCE_PACKAGE_VERSION),
  })
  .strict();

export const VerifiedKyaAuthorityBindingV1Schema = z
  .object({
    version: z.literal("inntris-kya-authority-binding-v1"),
    status: z.literal("verified"),
    profile: KyaProfileSchema,
    protocol_version: z.literal(KYA_PROTOCOL_VERSION),
    reference_implementation: BindingReferenceImplementationSchema,
    authority_policy_hash: HashSchema,
    presentation_hash: HashSchema,
    proof_hash: HashSchema,
    request_hash: HashSchema,
    delegation_chain_hash: HashSchema,
    entity_card_hash: HashSchema.nullable(),
    agent_did: z.string().min(1),
    responsible_party_did: z.string().min(1),
    principal_did: z.string().min(1).nullable(),
    proof_assurance: KyaProofAssuranceSchema,
    invocation_target: z.string().min(1),
    allowed_action: z.literal("payments.transfer"),
    max_amount: KyaAmountSchema.nullable(),
    currency: z.string().min(1).nullable(),
    delegation_depth: z.number().int().min(1).max(10),
    revocation_fresh: z.boolean(),
    signatures_verified: z.literal(true),
    verified_at: IsoTimestampSchema,
    authority_expires_at: IsoTimestampSchema,
    authority_hash: HashSchema,
  })
  .strict();

export const RejectedKyaAuthorityBindingV1Schema = z
  .object({
    version: z.literal("inntris-kya-authority-binding-v1"),
    status: z.literal("rejected"),
    profile: KyaProfileSchema,
    authority_policy_hash: HashSchema,
    presentation_hash: HashSchema,
    failure_stage: z.enum([
      "presentation",
      "request_proof",
      "delegation_signature",
      "delegation",
      "revocation",
      "financial_join",
      "state",
    ]),
  })
  .strict();

export const KyaAuthorityBindingV1Schema = z.discriminatedUnion("status", [
  VerifiedKyaAuthorityBindingV1Schema,
  RejectedKyaAuthorityBindingV1Schema,
]);

export const KyaDecisionAuthorityRecordSchema = z
  .object({
    decision_id: z.string().min(1),
    action_hash: HashSchema,
    action: InntrisActionV1Schema,
    binding: VerifiedKyaAuthorityBindingV1Schema,
    created_at: IsoTimestampSchema,
  })
  .strict();

export const KyaAuthorityRevalidationRecordSchema = z
  .object({
    id: z.uuid(),
    decision_id: z.string().min(1),
    action_hash: HashSchema,
    kind: z.enum(["approval", "consumption"]),
    execution_ref: z.string().min(1).nullable(),
    approval_reference: z.string().min(1).nullable(),
    presentation_hash: HashSchema,
    authority_hash: HashSchema.nullable(),
    status: z.enum(["verified", "rejected"]),
    reason_code: z.string().min(1).nullable(),
    verified_at: IsoTimestampSchema,
  })
  .strict();

export const KyaBoundActionSchema = InntrisActionV1Schema.refine(
  (action) => action.extensions?.[KYA_AUTHORITY_EXTENSION_KEY] !== undefined,
  "Verified KYA extension is required",
);

export type KyaToolRequest = z.infer<typeof KyaToolRequestSchema>;
export type KyaPaymentRequestV1 = z.infer<typeof KyaPaymentRequestV1Schema>;
export type KyaAuthorityPresentation = z.infer<typeof KyaAuthorityPresentationSchema>;
export type KyaEntityCardAuthorityPresentation = z.infer<
  typeof KyaEntityCardAuthorityPresentationSchema
>;
export type KyaLegacyAuthorityPresentation = z.infer<typeof KyaLegacyAuthorityPresentationSchema>;
export type KyaAuthorityPolicyV1 = z.infer<typeof KyaAuthorityPolicyV1Schema>;
export type KyaAuthorityBindingV1 = z.infer<typeof KyaAuthorityBindingV1Schema>;
export type VerifiedKyaAuthorityBindingV1 = z.infer<typeof VerifiedKyaAuthorityBindingV1Schema>;
export type RejectedKyaAuthorityBindingV1 = z.infer<typeof RejectedKyaAuthorityBindingV1Schema>;
export type KyaDecisionAuthorityRecord = z.infer<typeof KyaDecisionAuthorityRecordSchema>;
export type KyaAuthorityRevalidationRecord = z.infer<typeof KyaAuthorityRevalidationRecordSchema>;
