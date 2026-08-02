import { randomBytes } from "node:crypto";

import {
  hashAction,
  hashCanonical,
  InntrisActionV1Schema,
  InntrisDecisionV1Schema,
  type InntrisActionV1,
  type InntrisDecisionV1,
  type SigningProvider,
} from "@inntris/decision-core";

import {
  MtpApprovedResponseSchema,
  MtpSignedVerifyRequestSchema,
  MtpTokenResponseSchema,
  type MtpAuthorizationRecord,
  type MtpConsumptionReceipt,
  type MtpSignedVerifyRequest,
} from "./types.js";

export interface MtpAuthorityClientOptions {
  apiUrl: string;
  agentId: string;
  signer: SigningProvider;
  policyHash?: string | undefined;
  timeoutMs?: number | undefined;
  fetchImplementation?: typeof fetch | undefined;
  clock?: { now(): Date } | undefined;
  nonceFactory?: (() => string) | undefined;
}

export class MtpAuthorityError extends Error {
  override readonly name: string = "MtpAuthorityError";
}

export class MtpAuthorityDeniedError extends MtpAuthorityError {
  override readonly name: string = "MtpAuthorityDeniedError";

  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

export class MtpConsumptionRejectedError extends MtpAuthorityError {
  override readonly name: string = "MtpConsumptionRejectedError";
}

export function assertSeparateSigningIdentities(
  decisionSigner: SigningProvider,
  mtpSigner: SigningProvider,
): void {
  if (Buffer.from(decisionSigner.publicKey).equals(Buffer.from(mtpSigner.publicKey))) {
    throw new Error("The MTP agent signer must not reuse the Decision Envelope signing key");
  }
}

function rawHash(value: unknown): string {
  return hashCanonical(value).slice("sha256:".length);
}

function normalizePolicyHash(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  const raw = value.startsWith("sha256:") ? value.slice("sha256:".length) : value;
  if (!/^[0-9a-f]{64}$/u.test(raw)) {
    throw new TypeError("MTP policy hash must be a lowercase SHA-256 digest");
  }
  return raw;
}

/** Match MTP's Python datetime.isoformat() UTC wire representation exactly. */
export function canonicalMtpTimestamp(value: Date): string {
  if (Number.isNaN(value.getTime())) {
    throw new TypeError("MTP request timestamp must be a valid date");
  }
  const iso = value.toISOString();
  const match = /^(.*)\.(\d{3})Z$/u.exec(iso);
  if (match?.[1] === undefined || match[2] === undefined) {
    throw new TypeError("MTP request timestamp could not be canonicalised");
  }
  const wholeSeconds = match[1];
  const milliseconds = match[2];
  return milliseconds === "000" ? `${wholeSeconds}Z` : `${wholeSeconds}.${milliseconds}000Z`;
}

export function actionToMtpPayload(
  action: InntrisActionV1,
  decision: InntrisDecisionV1,
): Record<string, unknown> {
  const validatedAction = InntrisActionV1Schema.parse(action);
  const validatedDecision = InntrisDecisionV1Schema.parse(decision);
  if (validatedDecision.action_hash !== hashAction(validatedAction)) {
    throw new TypeError("The MTP authorization decision is not bound to the supplied action");
  }
  return {
    version: "inntris-mtp-authority-v1",
    amount: validatedAction.transaction.amount,
    currency: validatedAction.transaction.asset,
    recipient: validatedAction.transaction.payee,
    network: validatedAction.transaction.network,
    purpose: validatedAction.transaction.purpose,
    resource: validatedAction.protocol_reference.resource,
    rail: validatedAction.rail,
    principal_id: validatedAction.principal_id,
    declared_agent_id: validatedAction.agent_id,
    inntris_action: validatedAction,
    inntris_action_hash: validatedDecision.action_hash,
    inntris_decision_id: validatedDecision.decision_id,
    inntris_decision_fingerprint: validatedDecision.decision_fingerprint,
    inntris_policy_hash: validatedDecision.policy.policy_hash,
    inntris_policy_version: validatedDecision.policy.policy_version,
  };
}

export class MtpAuthorityClient {
  readonly #apiUrl: URL;
  readonly #fetch: typeof fetch;
  readonly #timeoutMs: number;
  readonly #clock: { now(): Date };
  readonly #nonceFactory: () => string;
  readonly #policyHash: string | undefined;

  constructor(readonly options: MtpAuthorityClientOptions) {
    this.#apiUrl = new URL(options.apiUrl);
    const localHosts = new Set(["127.0.0.1", "localhost", "::1", "[::1]"]);
    if (
      this.#apiUrl.protocol !== "https:" &&
      !(this.#apiUrl.protocol === "http:" && localHosts.has(this.#apiUrl.hostname))
    ) {
      throw new TypeError("MTP API URL must use HTTPS except for a loopback development URL");
    }
    if (this.#apiUrl.username !== "" || this.#apiUrl.password !== "") {
      throw new TypeError("MTP API URL must not contain credentials");
    }
    MtpSignedVerifyRequestSchema.shape.agent_id.parse(options.agentId);
    this.#fetch = options.fetchImplementation ?? fetch;
    this.#timeoutMs = options.timeoutMs ?? 10_000;
    this.#clock = options.clock ?? { now: () => new Date() };
    this.#nonceFactory = options.nonceFactory ?? (() => randomBytes(24).toString("base64url"));
    this.#policyHash = normalizePolicyHash(options.policyHash);
  }

  async #post(path: string, body: unknown): Promise<{ status: number; body: unknown }> {
    let response: Response;
    try {
      response = await this.#fetch(new URL(path, this.#apiUrl), {
        method: "POST",
        redirect: "error",
        signal: AbortSignal.timeout(this.#timeoutMs),
        headers: { accept: "application/json", "content-type": "application/json" },
        body: JSON.stringify(body),
      });
    } catch {
      throw new MtpAuthorityError("MTP service is unavailable");
    }
    let responseBody: unknown;
    try {
      responseBody = await response.json();
    } catch {
      throw new MtpAuthorityError("MTP returned a non-JSON response");
    }
    return { status: response.status, body: responseBody };
  }

  async #signedRequest(payload: Record<string, unknown>): Promise<{
    request: MtpSignedVerifyRequest;
    actionHash: string;
  }> {
    const nonce = this.#nonceFactory();
    const timestamp = canonicalMtpTimestamp(this.#clock.now());
    const signingEnvelope = {
      agent_id: this.options.agentId,
      action_type: "financial_transaction",
      payload_hash: rawHash(payload),
      nonce,
      timestamp,
    };
    const actionHash = rawHash(signingEnvelope);
    const signatureUrl = await this.options.signer.sign(Buffer.from(actionHash, "hex"));
    const request = MtpSignedVerifyRequestSchema.parse({
      agent_id: this.options.agentId,
      action_type: "financial_transaction",
      payload,
      nonce,
      timestamp,
      signature: Buffer.from(signatureUrl, "base64url").toString("base64"),
      sig_version: 3,
      ...(this.#policyHash === undefined ? {} : { policy_hash: this.#policyHash }),
    });
    return { request, actionHash };
  }

  async authorize(
    action: InntrisActionV1,
    decision: InntrisDecisionV1,
  ): Promise<MtpAuthorizationRecord> {
    const payload = actionToMtpPayload(action, decision);
    const signed = await this.#signedRequest(payload);
    const response = await this.#post("/verify", signed.request);
    if (response.status !== 200) {
      throw new MtpAuthorityDeniedError("MTP rejected the proposed execution", response.status);
    }
    const approved = MtpApprovedResponseSchema.parse(response.body);
    return {
      decisionId: decision.decision_id,
      actionHash: decision.action_hash,
      request: signed.request,
      mtpActionHash: signed.actionHash,
      approvalToken: approved.approval_token,
      authorizationAuditId: approved.audit_id,
      authorizedAt: approved.timestamp,
    };
  }

  async consume(
    authorization: MtpAuthorizationRecord,
    executionRef: string,
  ): Promise<MtpConsumptionReceipt> {
    const request = authorization.request;
    const response = await this.#post("/verify-token", {
      approval_token: authorization.approvalToken,
      agent_id: request.agent_id,
      action_type: request.action_type,
      payload: request.payload,
      nonce: request.nonce,
      timestamp: request.timestamp,
      sig_version: request.sig_version,
      consume: true,
      execution_ref: executionRef,
    });
    if (response.status !== 200) {
      throw new MtpConsumptionRejectedError("MTP token consumption was rejected");
    }
    const consumed = MtpTokenResponseSchema.parse(response.body);
    if (!consumed.valid) {
      throw new MtpConsumptionRejectedError("MTP token is not valid for this execution");
    }
    if (
      consumed.verdict !== "approved" ||
      consumed.agent_id !== request.agent_id ||
      consumed.action_hash !== authorization.mtpActionHash ||
      consumed.action_hash_matches !== true ||
      consumed.execution_ref !== executionRef ||
      consumed.sandbox !== false ||
      consumed.consumption_audit_id == null ||
      consumed.consumption_status == null
    ) {
      throw new MtpConsumptionRejectedError("MTP consumption evidence does not match the request");
    }
    return {
      executionRef,
      consumptionAuditId: consumed.consumption_audit_id,
      status: consumed.consumption_status,
    };
  }
}
