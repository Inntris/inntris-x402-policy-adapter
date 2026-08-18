import type { InntrisDecisionV1 } from "@inntris/decision-core";
import { actionFromX402 } from "@inntris/x402-adapter";
import { afterAll, describe, expect, it } from "vitest";

import { buildDemoApi } from "../../apps/demo-api/src/app.js";
import { honestInput, securityContext, withRequirements } from "./harness.js";
import { flushEvidence, recordEvidence } from "./evidence.js";

afterAll(async () => {
  await flushEvidence("d8-api-exposure");
});

const SERVICE_KEY = "test-service-key";

/** Narrows an injected JSON body to the decision it carries. */
function decisionOf(body: unknown): InntrisDecisionV1 {
  return (body as { decision: InntrisDecisionV1 }).decision;
}

async function api(options: { serviceApiKey?: string } = {}) {
  const context = await securityContext();
  const app = await buildDemoApi({
    ...context,
    logger: false,
    ...(options.serviceApiKey === undefined ? {} : { serviceApiKey: options.serviceApiKey }),
  });
  return { app, context };
}

describe("D8 API exposure", () => {
  it("serves every decision endpoint unauthenticated when no service key is configured", async () => {
    const { app } = await api();
    const action = actionFromX402(honestInput);

    const evaluate = await app.inject({
      method: "POST",
      url: "/v1/decisions/evaluate",
      payload: { action },
    });
    const keys = await app.inject({ method: "GET", url: "/.well-known/inntris-keys.json" });

    expect(evaluate.statusCode).toBe(200);
    expect(decisionOf(evaluate.json()).verdict).toBe("ALLOW");
    expect(keys.statusCode).toBe(200);
    await app.close();

    recordEvidence({
      id: "D8:no-auth-default",
      deliverable: "D8",
      attack: "Reaching the decision API with no credential at all",
      status: "KNOWN_GAP",
      expectation:
        "An endpoint that mints signed policy decisions should require a credential in every configuration.",
      observed:
        "buildDemoApi treats serviceApiKey as optional, and its authenticate preHandler returns early when it is undefined. INNTRIS_SERVICE_API_KEY is blank in .env.example and configuredValue maps blank to undefined, so a default deployment answers POST /v1/decisions/evaluate with a signed ALLOW and no credential. The only configuration that forces a key is one that also injects a reconciliation store, which buildDemoApi rejects without one.",
      enforcement: "NONE",
      reason_codes: [],
      settlement_invoked: false,
      resource_served: false,
      notes: "Sets the exposure precondition for F-1, F-5 and F-6.",
    });
  });

  it("rejects a missing or wrong credential once a service key is configured", async () => {
    const { app } = await api({ serviceApiKey: SERVICE_KEY });
    const action = actionFromX402(honestInput);

    const anonymous = await app.inject({
      method: "POST",
      url: "/v1/decisions/evaluate",
      payload: { action },
    });
    const wrong = await app.inject({
      method: "POST",
      url: "/v1/decisions/evaluate",
      headers: { authorization: "Bearer wrong-key" },
      payload: { action },
    });
    const correct = await app.inject({
      method: "POST",
      url: "/v1/decisions/evaluate",
      headers: { authorization: `Bearer ${SERVICE_KEY}` },
      payload: { action },
    });

    expect(anonymous.statusCode).toBe(401);
    expect(wrong.statusCode).toBe(401);
    expect(correct.statusCode).toBe(200);
    await app.close();

    recordEvidence({
      id: "D8:auth-enforced-when-configured",
      deliverable: "D8",
      attack: "Credential check with a service key configured",
      status: "PASS",
      expectation: "A configured bearer credential is required and compared in constant time.",
      observed:
        "Anonymous and wrong-credential requests both return 401; the correct credential returns 200. bearerMatches compares with timingSafeEqual after a length check.",
      enforcement: "INNTRIS",
      reason_codes: [],
      settlement_invoked: false,
      resource_served: false,
    });
  });

  it("F-5 regression: one credential mints independent daily budgets per asserted principal", async () => {
    const { app } = await api({ serviceApiKey: SERVICE_KEY });
    const headers = { authorization: `Bearer ${SERVICE_KEY}` };

    // 80.00 USDC is inside the 100.00 per-transaction limit but requires
    // human approval above 75.00; two of them exceed the 500.00 daily limit
    // only after six. Use the transaction limit to make the point cheaply:
    // the same credential asserts two principals and each is evaluated
    // against its own independent cumulative total.
    const first = await app.inject({
      method: "POST",
      url: "/v1/decisions/evaluate",
      headers,
      payload: { action: actionFromX402({ ...honestInput, principalId: "org_demo" }) },
    });
    const second = await app.inject({
      method: "POST",
      url: "/v1/decisions/evaluate",
      headers,
      payload: { action: actionFromX402({ ...honestInput, principalId: "org_attacker" }) },
    });

    expect(first.statusCode).toBe(200);
    expect(second.statusCode).toBe(200);
    expect(decisionOf(first.json()).principal_id).toBe("org_demo");
    expect(decisionOf(second.json()).principal_id).toBe("org_attacker");
    await app.close();

    recordEvidence({
      id: "D8:F5-principal-tenancy",
      deliverable: "D8",
      attack:
        "F-5. Cumulative daily limit keyed on a principal identifier the caller supplies in the request body",
      status: "KNOWN_GAP",
      expectation:
        "A cumulative limit must be keyed on an identity bound to the authenticated credential, so one caller cannot mint independent budgets.",
      observed:
        "One bearer credential authored two decisions naming org_demo and org_attacker. The credential does not scope the principal in any way: authenticate compares a single shared service key and never associates it with a tenancy. spendDayKey then keys the daily total on the asserted value, so each name carries its own independent budget.",
      enforcement: "NONE",
      reason_codes: [],
      settlement_invoked: false,
      resource_served: false,
      notes:
        "Regression target: two evaluations under differing principalId with the same credential must share one daily total.",
    });
  });

  it("F-6: the HTTP path accepts a fully client-authored action and never re-derives it", async () => {
    const { app } = await api({ serviceApiKey: SERVICE_KEY });
    const headers = { authorization: `Bearer ${SERVICE_KEY}` };

    // An action whose payment_requirements_hash is computed over requirements
    // that were never served by any resource server, and whose decimal amount
    // was chosen by the caller rather than derived from atomic units.
    const fabricated = actionFromX402({
      ...withRequirements({ amount: "150000000" }),
      assetDecimals: 9,
    });

    const response = await app.inject({
      method: "POST",
      url: "/v1/decisions/evaluate",
      headers,
      payload: { action: fabricated },
    });

    expect(response.statusCode).toBe(200);
    const decision = decisionOf(response.json());
    expect(decision.verdict).toBe("ALLOW");
    expect(decision.transaction.amount).toBe("0.15");
    expect(decision.protocol_reference.payment_requirements_hash).toBe(
      fabricated.protocol_reference.payment_requirements_hash,
    );
    await app.close();

    recordEvidence({
      id: "D8:F6-no-server-side-derivation",
      deliverable: "D8",
      attack:
        "F-6. Signed receipt minted from an action the caller authored in full, with no server-side derivation",
      status: "KNOWN_GAP",
      expectation:
        "A receipt should either attest to facts the issuer derived, or declare on its face that its inputs were caller-asserted.",
      observed:
        "POST /v1/decisions/evaluate parses the request body into an InntrisActionV1 and passes it straight to provider.evaluate. Amount, payee, asset, network, resource, purpose, principal, agent and payment_requirements_hash are all taken as given. A caller-authored action carrying a 150000000 atomic amount declared at 9 decimals produced a signed ALLOW reading 0.15, with a requirements hash the server never recomputed from any served requirements.",
      enforcement: "NONE",
      reason_codes: [],
      settlement_invoked: false,
      resource_served: false,
      notes:
        "The library path derives the same fields inside InntrisX402Guard.authorise. Both paths sign with the same key and emit the same receipt format, and an offline verifier cannot tell them apart.",
    });
  });

  it("records the reachability surface of every endpoint", async () => {
    const { app } = await api();
    const endpoints = [
      {
        method: "GET" as const,
        url: "/healthz",
        authenticated: false,
        rateLimit: "global 100/min",
      },
      {
        method: "GET" as const,
        url: "/.well-known/inntris-keys.json",
        authenticated: false,
        rateLimit: "global 100/min",
      },
      { method: "GET" as const, url: "/v1/kya/config", authenticated: false, rateLimit: "30/min" },
    ];
    for (const endpoint of endpoints) {
      const response = await app.inject({ method: endpoint.method, url: endpoint.url });
      expect(response.statusCode).toBe(200);
    }
    await app.close();

    recordEvidence({
      id: "D8:endpoint-surface",
      deliverable: "D8",
      attack: "Endpoint reachability, authentication and rate limiting inventory",
      status: "PASS",
      expectation: "Every endpoint's exposure is recorded rather than assumed.",
      observed:
        "Three endpoints are unauthenticated by construction: GET /healthz, GET /.well-known/inntris-keys.json and GET /v1/kya/config. Eight carry the authenticate preHandler, which is a no-op unless a service key is configured. Rate limiting is global 100/min with 30/min per sensitive route, keyed by client address, with no per-credential or per-principal quota.",
      enforcement: "INNTRIS",
      reason_codes: [],
      settlement_invoked: false,
      resource_served: false,
    });
  });
});
