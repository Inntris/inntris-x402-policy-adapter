import { readFile } from "node:fs/promises";

import { CanonicalAmountSchema, IsoTimestampSchema } from "@inntris/decision-core";
import { parse } from "yaml";
import { z } from "zod";

export const DEFAULT_APPROVAL_REQUEST_TTL_SECONDS = 900;

const WeekdaySchema = z.enum([
  "MONDAY",
  "TUESDAY",
  "WEDNESDAY",
  "THURSDAY",
  "FRIDAY",
  "SATURDAY",
  "SUNDAY",
]);

const TimeSchema = z.string().regex(/^(?:[01]\d|2[0-3]):[0-5]\d$/u);

const MerchantSchema = z
  .object({
    merchant_id: z.string().min(1).max(128),
    payees: z.array(z.string().min(1).max(512)).min(1),
    purposes: z.array(z.string().min(1).max(128)).min(1),
    resources: z.array(z.url()).min(1),
    per_transaction_limit: CanonicalAmountSchema,
  })
  .strict();

const DenySchema = z
  .object({
    networks: z.array(z.string()).default([]),
    assets: z.array(z.string()).default([]),
    payees: z.array(z.string()).default([]),
    purposes: z.array(z.string()).default([]),
    resources: z.array(z.url()).default([]),
  })
  .strict();

const RailPolicySchema = z
  .object({
    allowed_networks: z.array(z.string().min(1)).min(1),
    allowed_assets: z.array(z.string().min(1)).min(1),
  })
  .strict();

export const InntrisPolicyV1Schema = z
  .object({
    version: z.literal(1),
    policy_id: z.string().min(1).max(128),
    policy_version: z.string().min(1).max(64),
    expires_at: IsoTimestampSchema.optional(),
    defaults: z
      .object({
        verdict: z.literal("BLOCK"),
        decision_ttl_seconds: z.number().int().min(1).max(300),
      })
      .strict(),
    deny: DenySchema.optional(),
    rails: z
      .object({
        x402: RailPolicySchema,
        ap2: RailPolicySchema.optional(),
        evm: RailPolicySchema.optional(),
      })
      .strict(),
    limits: z
      .object({
        per_transaction: CanonicalAmountSchema,
        daily: CanonicalAmountSchema,
      })
      .strict(),
    approval: z
      .object({
        require_human_above: CanonicalAmountSchema,
        /**
         * How long a `REQUIRE_APPROVAL` decision stays resolvable, measured
         * from its `issued_at`. It is deliberately independent of
         * `decision_ttl_seconds`, because a human takes longer to answer than
         * a signed decision stays valid. Omitted policies use
         * `DEFAULT_APPROVAL_REQUEST_TTL_SECONDS`, which keeps the hashed
         * policy object unchanged.
         */
        request_ttl_seconds: z.number().int().min(1).max(86_400).optional(),
      })
      .strict(),
    merchants: z.array(MerchantSchema).min(1),
    time_windows: z
      .object({
        timezone: z.string().min(1).max(128),
        allowed_weekdays: z.array(WeekdaySchema).min(1),
        start: TimeSchema,
        end: TimeSchema,
      })
      .strict(),
  })
  .strict()
  .superRefine((policy, context) => {
    try {
      new Intl.DateTimeFormat("en-GB", { timeZone: policy.time_windows.timezone }).format(
        new Date(),
      );
    } catch {
      context.addIssue({
        code: "custom",
        message: "Unknown IANA timezone",
        path: ["time_windows", "timezone"],
      });
    }
  });

export type InntrisPolicyV1 = z.infer<typeof InntrisPolicyV1Schema>;
export type Weekday = z.infer<typeof WeekdaySchema>;

export function parsePolicyText(source: string): InntrisPolicyV1 {
  const parsed: unknown = parse(source);
  return InntrisPolicyV1Schema.parse(parsed);
}

export async function loadPolicyFile(path: string): Promise<InntrisPolicyV1> {
  return parsePolicyText(await readFile(path, "utf8"));
}
