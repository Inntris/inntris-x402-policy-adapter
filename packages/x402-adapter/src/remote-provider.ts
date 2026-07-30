import {
  InntrisDecisionV1Schema,
  KeyRegistrySchema,
  ReasonCodeSchema,
  type ConsumeDecisionInput,
  type ConsumeDecisionResult,
  type DecisionProvider,
  type InntrisActionV1,
  type InntrisDecisionV1,
  type KeyRegistry,
  type ResolveApprovalInput,
  type ResolveApprovalResult,
} from "@inntris/decision-core";
import {
  fetchExplicitKeyRegistry,
  verifyDecision,
  verifySignedDecision,
} from "@inntris/decision-verifier";
import { z } from "zod";

const ConsumeResultSchema = z
  .object({
    success: z.boolean(),
    status: z.enum(["consumed", "idempotent", "conflict", "rejected"]),
    decision_id: z.string(),
    execution_ref: z.string(),
    consumed_at: z.string().optional(),
    reason_code: ReasonCodeSchema.optional(),
  })
  .strict()
  .superRefine((result, context) => {
    const shouldSucceed = result.status === "consumed" || result.status === "idempotent";
    if (result.success !== shouldSucceed) {
      context.addIssue({
        code: "custom",
        message: "Consumption success does not match its status",
        path: ["success"],
      });
    }
    if (!result.success && result.reason_code === undefined) {
      context.addIssue({
        code: "custom",
        message: "Rejected consumption requires a reason code",
        path: ["reason_code"],
      });
    }
  });

const ResolveApprovalResultSchema = z
  .object({
    success: z.boolean(),
    status: z.enum(["superseded", "conflict", "rejected"]),
    decision_id: z.string(),
    decision: InntrisDecisionV1Schema.optional(),
    reason_code: ReasonCodeSchema.optional(),
  })
  .strict()
  .superRefine((result, context) => {
    if (result.success !== (result.status === "superseded")) {
      context.addIssue({
        code: "custom",
        message: "Approval success does not match its status",
        path: ["success"],
      });
    }
    if (result.success && result.decision === undefined) {
      context.addIssue({
        code: "custom",
        message: "A superseded approval requires the new decision",
        path: ["decision"],
      });
    }
    if (!result.success && result.reason_code === undefined) {
      context.addIssue({
        code: "custom",
        message: "Rejected approval resolution requires a reason code",
        path: ["reason_code"],
      });
    }
  });

export interface RemoteInntrisDecisionProviderOptions {
  apiUrl: string;
  apiKey: string;
  keyRegistry: KeyRegistry;
  expectedPolicyVersion?: string | undefined;
  timeoutMs?: number | undefined;
  fetchImplementation?: typeof fetch | undefined;
}

export class RemoteInntrisDecisionProviderError extends Error {
  override readonly name = "RemoteInntrisDecisionProviderError";
}

export class RemoteInntrisDecisionProvider implements DecisionProvider {
  readonly #apiUrl: URL;
  readonly #fetch: typeof fetch;
  readonly #timeoutMs: number;

  constructor(readonly options: RemoteInntrisDecisionProviderOptions) {
    this.#apiUrl = new URL(options.apiUrl);
    const localHosts = new Set(["127.0.0.1", "localhost", "::1", "[::1]"]);
    if (
      this.#apiUrl.protocol !== "https:" &&
      !(this.#apiUrl.protocol === "http:" && localHosts.has(this.#apiUrl.hostname))
    ) {
      throw new TypeError("INNTRIS_API_URL must use HTTPS except for a loopback development URL");
    }
    if (this.#apiUrl.username !== "" || this.#apiUrl.password !== "") {
      throw new TypeError("INNTRIS_API_URL must not contain credentials");
    }
    if (options.apiKey.length === 0) {
      throw new TypeError("INNTRIS_API_KEY must not be empty");
    }
    this.#fetch = options.fetchImplementation ?? fetch;
    this.#timeoutMs = options.timeoutMs ?? 10_000;
    KeyRegistrySchema.parse(options.keyRegistry);
  }

  /**
   * `acceptedRejectionStatuses` are statuses that carry a structured protocol
   * rejection rather than a technical failure, such as a replay conflict. Their
   * body is parsed and returned so the caller keeps the precise reason code
   * instead of collapsing it into an availability error.
   */
  async #post(
    path: string,
    body: unknown,
    acceptedRejectionStatuses: readonly number[] = [],
  ): Promise<unknown> {
    let response: Response;
    try {
      response = await this.#fetch(new URL(path, this.#apiUrl), {
        method: "POST",
        redirect: "error",
        signal: AbortSignal.timeout(this.#timeoutMs),
        headers: {
          accept: "application/json",
          authorization: `Bearer ${this.options.apiKey}`,
          "content-type": "application/json",
        },
        body: JSON.stringify(body),
      });
    } catch {
      throw new RemoteInntrisDecisionProviderError("Remote Inntris service is unavailable");
    }
    if (!response.ok && !acceptedRejectionStatuses.includes(response.status)) {
      throw new RemoteInntrisDecisionProviderError(
        `Remote Inntris request failed with HTTP ${response.status}`,
      );
    }
    return response.json();
  }

  async evaluate(action: InntrisActionV1): Promise<InntrisDecisionV1> {
    const response = z
      .object({ decision: InntrisDecisionV1Schema })
      .strict()
      .parse(await this.#post("/v1/decisions/evaluate", { action }));
    const verification = verifyDecision({
      decision: response.decision,
      action,
      keyRegistry: this.options.keyRegistry,
      at: new Date(),
      expectedPolicyVersion: this.options.expectedPolicyVersion,
    });
    if (!verification.valid) {
      throw new RemoteInntrisDecisionProviderError(
        `Remote decision verification failed: ${verification.reason_codes.join(",")}`,
      );
    }
    return response.decision;
  }

  async resolveApproval(input: ResolveApprovalInput): Promise<ResolveApprovalResult> {
    const result = ResolveApprovalResultSchema.parse(
      await this.#post("/v1/decisions/approve", input, [409, 422]),
    );
    if (result.decision_id !== input.decision_id) {
      throw new RemoteInntrisDecisionProviderError(
        "Remote approval response does not match the request",
      );
    }
    if (result.decision !== undefined) {
      if (result.decision.supersedes_decision_id !== input.decision_id) {
        throw new RemoteInntrisDecisionProviderError(
          "The superseding decision does not reference the approved decision",
        );
      }
      const verification = verifySignedDecision(result.decision, this.options.keyRegistry);
      if (!verification.valid) {
        throw new RemoteInntrisDecisionProviderError(
          `Superseding decision verification failed: ${verification.reason_codes.join(",")}`,
        );
      }
    }
    return {
      success: result.success,
      status: result.status,
      decision_id: result.decision_id,
      ...(result.decision === undefined ? {} : { decision: result.decision }),
      ...(result.reason_code === undefined ? {} : { reason_code: result.reason_code }),
    };
  }

  async consume(input: ConsumeDecisionInput): Promise<ConsumeDecisionResult> {
    const result = ConsumeResultSchema.parse(
      await this.#post("/v1/decisions/consume", input, [409, 422]),
    );
    if (result.decision_id !== input.decision_id || result.execution_ref !== input.execution_ref) {
      throw new RemoteInntrisDecisionProviderError(
        "Remote consumption response does not match the request",
      );
    }
    return {
      success: result.success,
      status: result.status,
      decision_id: result.decision_id,
      execution_ref: result.execution_ref,
      ...(result.consumed_at === undefined ? {} : { consumed_at: result.consumed_at }),
      ...(result.reason_code === undefined ? {} : { reason_code: result.reason_code }),
    };
  }
}

export async function remoteProviderFromEnvironment(
  environment: NodeJS.ProcessEnv = process.env,
): Promise<RemoteInntrisDecisionProvider> {
  const apiUrl = environment.INNTRIS_API_URL;
  const apiKey = environment.INNTRIS_API_KEY;
  const registryUrl = environment.INNTRIS_KEY_REGISTRY_URL;
  if (apiUrl === undefined || apiKey === undefined || registryUrl === undefined) {
    throw new RemoteInntrisDecisionProviderError(
      "INNTRIS_API_URL, INNTRIS_API_KEY and INNTRIS_KEY_REGISTRY_URL are required",
    );
  }
  return new RemoteInntrisDecisionProvider({
    apiUrl,
    apiKey,
    keyRegistry: await fetchExplicitKeyRegistry(registryUrl),
    expectedPolicyVersion: environment.INNTRIS_EXPECTED_POLICY_VERSION,
  });
}
