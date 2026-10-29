import { hashCanonical, type InntrisActionV1 } from "@inntris/decision-core";
import { z } from "zod";

// Inspected source, not an accepted release claim. Phase 7A is concurrent work.
export const MTP_V05_INSPECTED_SHA = "e31bfdf8b0b2f67f9e5f8ebc3890e76f7d19bf56";
const digest = z.string().regex(/^[0-9a-f]{64}$/u);
export const ExecutionGrantSchema = z
  .object({
    grantId: z.uuid(),
    authorityToken: z.string().min(1).max(16384),
    executionActionHash: digest,
    executorBindingDigest: digest,
  })
  .strict();
export type ExecutionGrant = z.infer<typeof ExecutionGrantSchema>;

const ConsumptionSchema = z.object({
  outcome: z.enum(["authorised", "recovered", "rejected"]),
  may_execute: z.boolean(),
  grant_id: z.uuid().nullable(),
  consumption_audit_id: z.uuid().nullable(),
  execution_ref: z.string().nullable(),
  reason: z.string().nullable(),
});

export function secureServiceUrl(value: string): URL {
  const url = new URL(value);
  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash) {
    throw new Error("Service URL must use HTTPS without credentials, query or fragment");
  }
  return url;
}

export interface MtpExecutionClientOptions {
  apiUrl: string;
  apiKey: string;
  apiKeyId: string;
  organisationId: string;
  agentId: string;
  fetchImplementation?: typeof fetch;
  timeoutMs?: number;
}

export class MtpExecutionClient {
  readonly executorBindingDigest: string;
  readonly origin: string;
  readonly #options: MtpExecutionClientOptions;
  readonly #fetch: typeof fetch;

  constructor(options: MtpExecutionClientOptions) {
    const url = secureServiceUrl(options.apiUrl);
    if (url.pathname !== "/") throw new Error("MTP URL must name the API origin");
    z.uuid().parse(options.organisationId);
    z.uuid().parse(options.agentId);
    z.uuid().parse(options.apiKeyId);
    z.string()
      .min(1)
      .regex(/^[^\r\n]+$/u)
      .parse(options.apiKey);
    this.#options = { ...options };
    this.origin = url.origin;
    this.#fetch = options.fetchImplementation ?? fetch;
    this.executorBindingDigest = hashCanonical({
      format: "inntris-executor-binding-v1",
      organisation_id: options.organisationId,
      api_key_id: options.apiKeyId,
    }).slice(7);
  }

  bind(action: InntrisActionV1): { payload: Record<string, unknown>; executionActionHash: string } {
    if (
      action.agent_id !== this.#options.agentId ||
      action.principal_id !== this.#options.organisationId
    ) {
      throw new Error("Action identity differs from the configured executor principal");
    }
    const payload = {
      amount: action.transaction.amount,
      currency: action.transaction.asset,
      network: action.transaction.network,
      purpose: action.transaction.purpose,
      rail: action.rail,
      inntris_action: action,
    };
    // Exact target lifting for this one wire profile, from the inspected MTP adapter.
    const executionActionHash = hashCanonical({
      format: "inntris-execution-action-v1",
      principal: this.#options.agentId,
      organisation: this.#options.organisationId,
      domain: "payment",
      action_type: "financial_transaction",
      target: { resource_type: "account", resource_id: action.transaction.payee },
      payload,
    }).slice(7);
    return { payload: { ...payload, recipient: action.transaction.payee }, executionActionHash };
  }

  async #post(path: string, body: unknown): Promise<unknown> {
    const response = await this.#fetch(new URL(path, this.origin), {
      method: "POST",
      redirect: "error",
      headers: { "Content-Type": "application/json", "X-API-Key": this.#options.apiKey },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(this.#options.timeoutMs ?? 10000),
    });
    if (!response.ok) throw new Error("MTP refused or could not authenticate the executor");
    return response.json();
  }

  async evaluate(
    action: InntrisActionV1,
    issuanceRef: string,
    delegatedAuthority?: Record<string, unknown>,
  ): Promise<ExecutionGrant> {
    const bound = this.bind(action);
    const response = z
      .object({
        decision: z.literal("ALLOW"),
        grant_id: z.uuid(),
        authority_token: z.string().min(1),
        execution_action_hash: digest,
        expires_at: z.iso.datetime({ offset: true }),
      })
      .parse(
        await this.#post("/authority/evaluate", {
          agent_id: this.#options.agentId,
          action_type: "financial_transaction",
          payload: bound.payload,
          issuance_ref: z.string().min(1).max(512).parse(issuanceRef),
          ...(delegatedAuthority === undefined ? {} : { delegated_authority: delegatedAuthority }),
        }),
      );
    if (response.execution_action_hash !== bound.executionActionHash)
      throw new Error("MTP action hash mismatch");
    return ExecutionGrantSchema.parse({
      grantId: response.grant_id,
      authorityToken: response.authority_token,
      executionActionHash: response.execution_action_hash,
      executorBindingDigest: this.executorBindingDigest,
    });
  }

  async consume(
    bound: { payload: Record<string, unknown>; executionActionHash: string },
    grant: ExecutionGrant,
    executionRef: string,
  ) {
    if (
      grant.executorBindingDigest !== this.executorBindingDigest ||
      grant.executionActionHash !== bound.executionActionHash
    ) {
      throw new Error("Grant executor or exact action mismatch");
    }
    const result = ConsumptionSchema.parse(
      await this.#post("/authority/consume", {
        authority_token: grant.authorityToken,
        agent_id: this.#options.agentId,
        action_type: "financial_transaction",
        payload: bound.payload,
        execution_ref: executionRef,
      }),
    );
    if (
      result.outcome === "rejected" ||
      result.grant_id !== grant.grantId ||
      result.execution_ref !== executionRef ||
      result.consumption_audit_id === null ||
      result.may_execute !== (result.outcome === "authorised")
    ) {
      throw new Error("MTP consumption refused or returned conflicting evidence");
    }
    return { outcome: result.outcome, consumptionAuditId: result.consumption_audit_id };
  }
}
