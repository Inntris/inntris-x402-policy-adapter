import {
  Ed25519SigningProvider,
  buildKeyRegistryEntry,
  canonicalBytes,
  createSignedDecision,
  verifyEd25519Signature,
  type KeyRegistry,
} from "@inntris/decision-core";
import {
  ManagedSigningError,
  RemoteEd25519SigningProvider,
  assertRotationRegistry,
  assertSigningProviderRegistered,
} from "@inntris/managed-signing";
import { verifySignedDecision } from "@inntris/decision-verifier";
import { actionFromX402 } from "@inntris/x402-adapter";
import { describe, expect, it, vi } from "vitest";

import { bindingInput, MutableClock } from "../helpers.js";

const serviceSigner = Ed25519SigningProvider.fromSeed(
  "decision-key-2026-08",
  new Uint8Array(32).fill(9),
);
const substitutedSigner = Ed25519SigningProvider.fromSeed(
  "substituted-key",
  new Uint8Array(32).fill(8),
);

function response(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function signingService(options: { tamper?: boolean } = {}): typeof fetch {
  return vi.fn<typeof fetch>(async (_input, init) => {
    if (typeof init?.body !== "string") {
      throw new TypeError("Managed signer test requires a JSON request body");
    }
    const body = JSON.parse(init.body) as Record<string, unknown>;
    const payload = Buffer.from(String(body.payload_base64url), "base64url");
    const signature = await (options.tamper ? substitutedSigner : serviceSigner).sign(payload);
    return response({
      version: "inntris-sign-response-v1",
      alg: "Ed25519",
      key_id: serviceSigner.keyId,
      signature,
    });
  });
}

function remoteSigner(fetchImplementation: typeof fetch): RemoteEd25519SigningProvider {
  return new RemoteEd25519SigningProvider({
    endpointUrl: "https://signer.example.test/v1/sign",
    bearerToken: "test-bearer-token",
    keyId: serviceSigner.keyId,
    publicKeyBase64Url: Buffer.from(serviceSigner.publicKey).toString("base64url"),
    fetchImplementation,
  });
}

describe("managed signing", () => {
  it("verifies every remote Ed25519 signature against the pinned public key", async () => {
    const fetchImplementation = signingService();
    const signer = remoteSigner(fetchImplementation);
    const payload = canonicalBytes({ exact: "decision", amount: "4.50" });

    const signature = await signer.sign(payload);

    expect(verifyEd25519Signature(payload, signature, signer.publicKey)).toBe(true);
    expect(fetchImplementation).toHaveBeenCalledOnce();
    const request = vi.mocked(fetchImplementation).mock.calls[0];
    expect(request?.[1]?.headers).toMatchObject({
      authorization: "Bearer test-bearer-token",
    });
    const requestBody = request?.[1]?.body;
    if (typeof requestBody !== "string") {
      throw new TypeError("Managed signer request body was not JSON text");
    }
    const body = JSON.parse(requestBody) as Record<string, unknown>;
    expect(body).toMatchObject({
      version: "inntris-sign-request-v1",
      alg: "Ed25519",
      key_id: serviceSigner.keyId,
      payload_base64url: Buffer.from(payload).toString("base64url"),
    });
    expect(JSON.stringify(body)).not.toContain("test-bearer-token");
  });

  it("fails closed on a substituted remote signature", async () => {
    await expect(
      remoteSigner(signingService({ tamper: true })).sign(new Uint8Array([1])),
    ).rejects.toBeInstanceOf(ManagedSigningError);
  });

  it("requires HTTPS, explicit authentication and bounded payloads", async () => {
    expect(
      () =>
        new RemoteEd25519SigningProvider({
          endpointUrl: "http://signer.example.test/v1/sign",
          bearerToken: "token",
          keyId: serviceSigner.keyId,
          publicKeyBase64Url: Buffer.from(serviceSigner.publicKey).toString("base64url"),
        }),
    ).toThrow("must use HTTPS");
    expect(
      () =>
        new RemoteEd25519SigningProvider({
          endpointUrl: "https://signer.example.test/v1/sign",
          bearerToken: "",
          keyId: serviceSigner.keyId,
          publicKeyBase64Url: Buffer.from(serviceSigner.publicKey).toString("base64url"),
        }),
    ).toThrow("must not be empty");
    await expect(remoteSigner(signingService()).sign(new Uint8Array())).rejects.toThrow(
      "outside the configured limit",
    );
  });

  it("fails closed without exposing the credential when the service is unavailable", async () => {
    const unavailable = vi.fn<typeof fetch>(async () => {
      throw new Error("upstream failure containing test-bearer-token");
    });

    let error: unknown;
    try {
      await remoteSigner(unavailable).sign(new Uint8Array([1]));
    } catch (caught) {
      error = caught;
    }

    expect(error).toBeInstanceOf(ManagedSigningError);
    expect(String(error)).toContain("unavailable");
    expect(String(error)).not.toContain("test-bearer-token");
  });

  it("fails closed when the service changes the requested key identity", async () => {
    const changedKey = vi.fn<typeof fetch>(async (_input, init) => {
      if (typeof init?.body !== "string") {
        throw new TypeError("Managed signer test requires a JSON request body");
      }
      const body = JSON.parse(init.body) as Record<string, unknown>;
      const payload = Buffer.from(String(body.payload_base64url), "base64url");
      return response({
        version: "inntris-sign-response-v1",
        alg: "Ed25519",
        key_id: substitutedSigner.keyId,
        signature: await serviceSigner.sign(payload),
      });
    });

    await expect(remoteSigner(changedKey).sign(new Uint8Array([1]))).rejects.toThrow(
      "different key identity",
    );
  });

  it("keeps old decisions verifiable after a controlled key rotation", async () => {
    const oldSigner = Ed25519SigningProvider.fromSeed(
      "decision-key-2026-01",
      new Uint8Array(32).fill(3),
    );
    const newSigner = serviceSigner;
    const cutover = new Date("2026-08-01T00:00:00.000Z");
    const registry: KeyRegistry = assertRotationRegistry({
      version: "inntris-key-registry-v1",
      keys: [
        buildKeyRegistryEntry(oldSigner, {
          status: "retired",
          notBefore: new Date("2026-01-01T00:00:00.000Z"),
          notAfter: cutover,
        }),
        buildKeyRegistryEntry(newSigner, {
          status: "active",
          notBefore: cutover,
        }),
      ],
    });
    const action = actionFromX402(bindingInput);
    const evaluation = {
      verdict: "ALLOW" as const,
      reasonCodes: ["MERCHANT_ALLOWED" as const],
      approval: { mode: "policy_engine" as const, approval_reference: null, approver_ids: [] },
    };
    const oldDecision = await createSignedDecision({
      action,
      evaluation,
      policyHash: `sha256:${"a".repeat(64)}`,
      policyVersion: "1",
      decisionTtlSeconds: 60,
      signer: oldSigner,
      clock: new MutableClock(new Date("2026-07-31T23:59:00.000Z")),
    });
    const newDecision = await createSignedDecision({
      action,
      evaluation,
      policyHash: `sha256:${"a".repeat(64)}`,
      policyVersion: "1",
      decisionTtlSeconds: 60,
      signer: newSigner,
      clock: new MutableClock(new Date("2026-08-01T00:01:00.000Z")),
    });

    expect(verifySignedDecision(oldDecision, registry).valid).toBe(true);
    expect(verifySignedDecision(newDecision, registry).valid).toBe(true);
    expect(() =>
      assertSigningProviderRegistered(newSigner, registry, new Date("2026-08-01T00:01:00.000Z")),
    ).not.toThrow();
    expect(() =>
      assertSigningProviderRegistered(oldSigner, registry, new Date("2026-08-01T00:01:00.000Z")),
    ).toThrow("not an active registry key");
  });

  it("requires a retirement boundary and treats revocation as historical distrust", async () => {
    const retiredEntry = buildKeyRegistryEntry(substitutedSigner, {
      status: "retired",
      notBefore: new Date("2026-01-01T00:00:00.000Z"),
    });
    const activeEntry = buildKeyRegistryEntry(serviceSigner, {
      status: "active",
      notBefore: new Date("2026-08-01T00:00:00.000Z"),
    });
    expect(() =>
      assertRotationRegistry({
        version: "inntris-key-registry-v1",
        keys: [retiredEntry, activeEntry],
      }),
    ).toThrow("requires not_after");
    expect(() =>
      assertRotationRegistry({
        version: "inntris-key-registry-v1",
        keys: [
          buildKeyRegistryEntry(substitutedSigner, {
            status: "retired",
            notBefore: new Date("2026-08-02T00:00:00.000Z"),
            notAfter: new Date("2026-08-01T00:00:00.000Z"),
          }),
          activeEntry,
        ],
      }),
    ).toThrow("later than not_before");

    const action = actionFromX402(bindingInput);
    const decision = await createSignedDecision({
      action,
      evaluation: {
        verdict: "ALLOW",
        reasonCodes: ["MERCHANT_ALLOWED"],
        approval: { mode: "policy_engine", approval_reference: null, approver_ids: [] },
      },
      policyHash: `sha256:${"a".repeat(64)}`,
      policyVersion: "1",
      decisionTtlSeconds: 60,
      signer: serviceSigner,
      clock: new MutableClock(new Date("2026-08-01T00:01:00.000Z")),
    });
    const revoked = {
      version: "inntris-key-registry-v1" as const,
      keys: [
        buildKeyRegistryEntry(serviceSigner, {
          status: "revoked",
          notBefore: new Date("2026-01-01T00:00:00.000Z"),
        }),
      ],
    };
    expect(verifySignedDecision(decision, revoked)).toMatchObject({
      valid: false,
      reason_codes: ["UNKNOWN_SIGNING_KEY"],
    });
  });
});
