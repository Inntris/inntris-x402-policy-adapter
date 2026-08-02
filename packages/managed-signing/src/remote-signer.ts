import {
  Base64UrlSchema,
  IdentifierSchema,
  sha256Bytes,
  verifyEd25519Signature,
  type SigningProvider,
} from "@inntris/decision-core";
import { z } from "zod";

const SignResponseSchema = z
  .object({
    version: z.literal("inntris-sign-response-v1"),
    alg: z.literal("Ed25519"),
    key_id: IdentifierSchema,
    signature: Base64UrlSchema,
  })
  .strict();

export interface RemoteEd25519SigningProviderOptions {
  endpointUrl: string;
  bearerToken: string;
  keyId: string;
  publicKeyBase64Url: string;
  timeoutMs?: number | undefined;
  fetchImplementation?: typeof fetch | undefined;
  maxPayloadBytes?: number | undefined;
}

export class ManagedSigningError extends Error {
  override readonly name = "ManagedSigningError";
}

export class RemoteEd25519SigningProvider implements SigningProvider {
  readonly algorithm = "Ed25519" as const;
  readonly keyId: string;
  readonly publicKey: Uint8Array;
  readonly #endpoint: URL;
  readonly #fetch: typeof fetch;
  readonly #timeoutMs: number;
  readonly #bearerToken: string;
  readonly #maxPayloadBytes: number;

  constructor(options: RemoteEd25519SigningProviderOptions) {
    this.#endpoint = new URL(options.endpointUrl);
    const localHosts = new Set(["127.0.0.1", "localhost", "::1", "[::1]"]);
    if (
      this.#endpoint.protocol !== "https:" &&
      !(this.#endpoint.protocol === "http:" && localHosts.has(this.#endpoint.hostname))
    ) {
      throw new TypeError(
        "Managed signer URL must use HTTPS except for a loopback development URL",
      );
    }
    if (this.#endpoint.username !== "" || this.#endpoint.password !== "") {
      throw new TypeError("Managed signer URL must not contain credentials");
    }
    this.keyId = IdentifierSchema.parse(options.keyId);
    this.publicKey = Buffer.from(Base64UrlSchema.parse(options.publicKeyBase64Url), "base64url");
    if (this.publicKey.byteLength !== 32) {
      throw new TypeError("Managed signer public key must decode to 32 bytes");
    }
    if (options.bearerToken.trim() === "") {
      throw new TypeError("Managed signer bearer token must not be empty");
    }
    if (!Number.isSafeInteger(options.timeoutMs ?? 10_000) || (options.timeoutMs ?? 10_000) <= 0) {
      throw new TypeError("Managed signer timeout must be a positive integer");
    }
    if (
      !Number.isSafeInteger(options.maxPayloadBytes ?? 1_048_576) ||
      (options.maxPayloadBytes ?? 1_048_576) <= 0
    ) {
      throw new TypeError("Managed signer payload limit must be a positive integer");
    }
    this.#bearerToken = options.bearerToken;
    this.#fetch = options.fetchImplementation ?? fetch;
    this.#timeoutMs = options.timeoutMs ?? 10_000;
    this.#maxPayloadBytes = options.maxPayloadBytes ?? 1_048_576;
  }

  async sign(payload: Uint8Array): Promise<string> {
    if (payload.byteLength === 0 || payload.byteLength > this.#maxPayloadBytes) {
      throw new ManagedSigningError("Signing payload size is outside the configured limit");
    }
    let response: Response;
    try {
      response = await this.#fetch(this.#endpoint, {
        method: "POST",
        redirect: "error",
        signal: AbortSignal.timeout(this.#timeoutMs),
        headers: {
          accept: "application/json",
          authorization: `Bearer ${this.#bearerToken}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          version: "inntris-sign-request-v1",
          alg: this.algorithm,
          key_id: this.keyId,
          payload_base64url: Buffer.from(payload).toString("base64url"),
          payload_sha256: sha256Bytes(payload),
        }),
      });
    } catch {
      throw new ManagedSigningError("Managed signing service is unavailable");
    }
    if (!response.ok) {
      throw new ManagedSigningError(`Managed signing request failed with HTTP ${response.status}`);
    }
    let responseBody: unknown;
    try {
      responseBody = await response.json();
    } catch {
      throw new ManagedSigningError("Managed signing service returned non-JSON data");
    }
    const parsed = SignResponseSchema.safeParse(responseBody);
    if (!parsed.success) {
      throw new ManagedSigningError("Managed signing service returned an invalid response");
    }
    const signed = parsed.data;
    if (signed.key_id !== this.keyId) {
      throw new ManagedSigningError("Managed signer returned a different key identity");
    }
    if (!verifyEd25519Signature(payload, signed.signature, this.publicKey)) {
      throw new ManagedSigningError("Managed signer returned an invalid Ed25519 signature");
    }
    return signed.signature;
  }
}
