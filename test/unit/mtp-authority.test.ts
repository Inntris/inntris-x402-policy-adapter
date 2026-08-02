import {
  createPublicDemoSigner,
  Ed25519SigningProvider,
  hashCanonical,
  type ConsumeDecisionInput,
  type DecisionProvider,
} from "@inntris/decision-core";
import {
  InMemoryMtpAuthorityStateStore,
  assertSeparateSigningIdentities,
  canonicalMtpTimestamp,
  MtpAuthorityClient,
  MtpAuthorityDeniedError,
  MtpCompositeDecisionProvider,
} from "@inntris/mtp-authority";
import { actionFromX402, InntrisX402Guard } from "@inntris/x402-adapter";
import { describe, expect, it, vi } from "vitest";

import { bindingInput, testContext } from "../helpers.js";

const MTP_AGENT_ID = "00000000-0000-4000-8000-000000000123";
const AUTHORIZATION_AUDIT_ID = "00000000-0000-4000-8000-000000000124";
const CONSUMPTION_AUDIT_ID = "00000000-0000-4000-8000-000000000125";

function rawHash(value: unknown): string {
  return hashCanonical(value).slice("sha256:".length);
}

function mtpActionHash(body: Record<string, unknown>): string {
  return rawHash({
    agent_id: body.agent_id,
    action_type: body.action_type,
    payload_hash: rawHash(body.payload),
    nonce: body.nonce,
    timestamp: body.timestamp,
  });
}

function response(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function mtpFetch(
  options: {
    events?: string[];
    consume?: "consumed" | "idempotent" | "lost" | "mismatch";
    rejectAuthorization?: boolean;
  } = {},
): typeof fetch {
  let consumptionAttempts = 0;
  return vi.fn<typeof fetch>(async (input, init) => {
    const url = input instanceof Request ? new URL(input.url) : new URL(input);
    if (typeof init?.body !== "string") {
      throw new TypeError("MTP test requests require a JSON string body");
    }
    const body = JSON.parse(init.body) as Record<string, unknown>;
    if (url.pathname === "/verify") {
      options.events?.push("mtp-authorize");
      if (options.rejectAuthorization === true) {
        return response({ detail: "blocked" }, 403);
      }
      return response({
        verdict: "approved",
        approval_token: "test-approval-token",
        trust_score: 80,
        audit_id: AUTHORIZATION_AUDIT_ID,
        timestamp: "2026-07-29T12:00:00.000Z",
        limits_remaining: {},
      });
    }
    if (url.pathname === "/verify-token") {
      options.events?.push("mtp-consume");
      consumptionAttempts += 1;
      if (options.consume === "lost" && consumptionAttempts === 1) {
        throw new Error("response lost after remote consumption");
      }
      const requestPayload = body.payload;
      const request = {
        agent_id: body.agent_id,
        action_type: body.action_type,
        payload: requestPayload,
        nonce: body.nonce,
        timestamp: body.timestamp,
      };
      const actionHash = mtpActionHash(request);
      return response({
        valid: true,
        reason: null,
        verdict: "approved",
        agent_id: MTP_AGENT_ID,
        action_hash: options.consume === "mismatch" ? "0".repeat(64) : actionHash,
        expires_at: "2026-07-29T12:05:00.000Z",
        action_hash_matches: true,
        consumption_audit_id: CONSUMPTION_AUDIT_ID,
        consumption_status:
          options.consume === "lost" || options.consume === "idempotent"
            ? "idempotent"
            : "consumed",
        execution_ref: body.execution_ref,
        sandbox: false,
      });
    }
    return response({ detail: "not found" }, 404);
  });
}

function client(fetchImplementation: typeof fetch, clock: { now(): Date }): MtpAuthorityClient {
  return new MtpAuthorityClient({
    apiUrl: "https://mtp.example.test",
    agentId: MTP_AGENT_ID,
    signer: createPublicDemoSigner(),
    fetchImplementation,
    clock,
    nonceFactory: () => "test-mtp-nonce",
  });
}

describe("MTP authority composition", () => {
  it("matches MTP Python timestamp canonicalisation", () => {
    expect(canonicalMtpTimestamp(new Date("2026-07-29T12:00:00.000Z"))).toBe(
      "2026-07-29T12:00:00Z",
    );
    expect(canonicalMtpTimestamp(new Date("2026-07-29T12:00:00.123Z"))).toBe(
      "2026-07-29T12:00:00.123000Z",
    );
  });

  it("matches the MTP Python sig version 3 action hash", () => {
    const payload = {
      amount: "4.50",
      currency: "USDC",
      memo: "café",
      nested: { z: 1, a: true },
    };
    expect(
      rawHash({
        agent_id: MTP_AGENT_ID,
        action_type: "financial_transaction",
        payload_hash: rawHash(payload),
        nonce: "cross-language-nonce",
        timestamp: "2026-07-29T12:00:00.123000Z",
      }),
    ).toBe("ff7f3f2d7d9f67806618886f3a3d1d97cc8b308e05c6a19a15b9005e3f275c46");
  });

  it("signs RFC 8785 MTP requests over the exact action and decision", async () => {
    const context = await testContext();
    const action = actionFromX402(bindingInput);
    const decision = await context.provider.evaluate(action);
    const signer = createPublicDemoSigner();
    const sign = vi.spyOn(signer, "sign");
    const authority = new MtpAuthorityClient({
      apiUrl: "https://mtp.example.test",
      agentId: MTP_AGENT_ID,
      signer,
      fetchImplementation: mtpFetch(),
      clock: context.clock,
      nonceFactory: () => "test-mtp-nonce",
    });

    const record = await authority.authorize(action, decision);

    expect(record.request.payload).toMatchObject({
      version: "inntris-mtp-authority-v1",
      amount: "4.50",
      currency: "USDC",
      recipient: bindingInput.paymentRequirements.payTo,
      network: "eip155:8453",
      resource: bindingInput.resource,
      inntris_action: action,
      inntris_action_hash: decision.action_hash,
      inntris_decision_id: decision.decision_id,
      inntris_decision_fingerprint: decision.decision_fingerprint,
    });
    expect(sign).toHaveBeenCalledOnce();
    expect(Buffer.from(sign.mock.calls[0]![0]).toString("hex")).toBe(record.mtpActionHash);
    expect(record.request.signature).not.toContain("-");
    expect(record.request.signature).not.toContain("_");
  });

  it("consumes MTP, checkpoints its receipt, then consumes locally before settlement", async () => {
    const context = await testContext();
    const events: string[] = [];
    const inner: DecisionProvider = {
      evaluate: (action) => context.provider.evaluate(action),
      consume: async (input) => {
        events.push("inner-consume");
        return context.provider.consume(input);
      },
    };
    const composite = new MtpCompositeDecisionProvider({
      provider: inner,
      client: client(mtpFetch({ events }), context.clock),
      stateStore: new InMemoryMtpAuthorityStateStore(),
      clock: context.clock,
    });
    const guard = new InntrisX402Guard({
      provider: composite,
      keyRegistry: context.keyRegistry,
      expectedPolicyVersion: "1",
      clock: context.clock,
    });
    const decision = await guard.authorise(bindingInput);
    const settled = await guard.settleIfAuthorised(
      bindingInput,
      decision,
      "payment-123",
      async () => {
        events.push("settle");
        return "settled";
      },
    );

    expect(settled).toBe("settled");
    expect(events).toEqual(["mtp-authorize", "mtp-consume", "inner-consume", "settle"]);

    const retry = await composite.consume({
      decision_id: decision.decision_id,
      action_hash: decision.action_hash,
      execution_ref: "payment-123",
    });
    expect(retry).toMatchObject({ success: true, status: "idempotent" });
    expect(events).toEqual([
      "mtp-authorize",
      "mtp-consume",
      "inner-consume",
      "settle",
      "inner-consume",
    ]);

    const conflict = await composite.consume({
      decision_id: decision.decision_id,
      action_hash: decision.action_hash,
      execution_ref: "payment-456",
    });
    expect(conflict).toMatchObject({
      success: false,
      status: "conflict",
      reason_code: "NONCE_ALREADY_CONSUMED",
    });
  });

  it("recovers a lost MTP response with the same execution reference", async () => {
    const context = await testContext();
    const events: string[] = [];
    const innerConsume = vi.fn((input: ConsumeDecisionInput) => context.provider.consume(input));
    const composite = new MtpCompositeDecisionProvider({
      provider: {
        evaluate: (action) => context.provider.evaluate(action),
        consume: innerConsume,
      },
      client: client(mtpFetch({ events, consume: "lost" }), context.clock),
      stateStore: new InMemoryMtpAuthorityStateStore(),
      clock: context.clock,
    });
    const decision = await composite.evaluate(actionFromX402(bindingInput));
    const input = {
      decision_id: decision.decision_id,
      action_hash: decision.action_hash,
      execution_ref: "lost-response-123",
    };

    await expect(composite.consume(input)).rejects.toThrow("MTP service is unavailable");
    await expect(composite.consume(input)).resolves.toMatchObject({
      success: true,
      status: "consumed",
    });
    expect(events).toEqual(["mtp-authorize", "mtp-consume", "mtp-consume"]);
    expect(innerConsume).toHaveBeenCalledOnce();
  });

  it("fails closed on mismatched MTP consumption evidence", async () => {
    const context = await testContext();
    const innerConsume = vi.fn((input: ConsumeDecisionInput) => context.provider.consume(input));
    const composite = new MtpCompositeDecisionProvider({
      provider: {
        evaluate: (action) => context.provider.evaluate(action),
        consume: innerConsume,
      },
      client: client(mtpFetch({ consume: "mismatch" }), context.clock),
      stateStore: new InMemoryMtpAuthorityStateStore(),
    });
    const decision = await composite.evaluate(actionFromX402(bindingInput));

    await expect(
      composite.consume({
        decision_id: decision.decision_id,
        action_hash: decision.action_hash,
        execution_ref: "mismatch-123",
      }),
    ).resolves.toMatchObject({
      success: false,
      status: "rejected",
      reason_code: "DECISION_NOT_ALLOW",
    });
    expect(innerConsume).not.toHaveBeenCalled();
  });

  it("does not call MTP for a local block and rejects an MTP authorization denial", async () => {
    const context = await testContext();
    const blockedFetch = mtpFetch();
    const composite = new MtpCompositeDecisionProvider({
      provider: context.provider,
      client: client(blockedFetch, context.clock),
      stateStore: new InMemoryMtpAuthorityStateStore(),
    });
    const blockedAction = actionFromX402({
      ...bindingInput,
      paymentRequirements: { ...bindingInput.paymentRequirements, amount: "150000000" },
    });
    await expect(composite.evaluate(blockedAction)).resolves.toMatchObject({ verdict: "BLOCK" });
    expect(blockedFetch).not.toHaveBeenCalled();

    const denied = new MtpCompositeDecisionProvider({
      provider: context.provider,
      client: client(mtpFetch({ rejectAuthorization: true }), context.clock),
      stateStore: new InMemoryMtpAuthorityStateStore(),
    });
    await expect(denied.evaluate(actionFromX402(bindingInput))).rejects.toBeInstanceOf(
      MtpAuthorityDeniedError,
    );
  });

  it("requires HTTPS outside loopback and forbids credentials in the API URL", () => {
    const signer = createPublicDemoSigner();
    expect(
      () =>
        new MtpAuthorityClient({
          apiUrl: "http://mtp.example.test",
          agentId: MTP_AGENT_ID,
          signer,
        }),
    ).toThrow("must use HTTPS");
    expect(
      () =>
        new MtpAuthorityClient({
          apiUrl: "https://user:password@mtp.example.test",
          agentId: MTP_AGENT_ID,
          signer,
        }),
    ).toThrow("must not contain credentials");
  });

  it("rejects reuse of the Decision Envelope signing identity", () => {
    const decisionSigner = createPublicDemoSigner();
    const separateMtpSigner = Ed25519SigningProvider.fromSeed(
      "mtp-test-key",
      new Uint8Array(32).fill(7),
    );
    expect(() => assertSeparateSigningIdentities(decisionSigner, decisionSigner)).toThrow(
      "must not reuse",
    );
    expect(() => assertSeparateSigningIdentities(decisionSigner, separateMtpSigner)).not.toThrow();
  });
});
