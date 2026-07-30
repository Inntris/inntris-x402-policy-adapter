import { buildDemoApi } from "../../apps/demo-api/src/app.js";
import { describe, expect, it } from "vitest";

import { bindingInput, testContext } from "../helpers.js";
import { actionFromX402 } from "@inntris/x402-adapter";
import type { InntrisDecisionV1 } from "@inntris/decision-core";

describe("reference API", () => {
  it("serves health and the public key registry", async () => {
    const context = await testContext();
    const app = await buildDemoApi({ ...context, logger: false });
    const health = await app.inject({ method: "GET", url: "/healthz" });
    const keys = await app.inject({
      method: "GET",
      url: "/.well-known/inntris-keys.json",
    });
    expect(health.statusCode).toBe(200);
    expect(health.json()).toMatchObject({ status: "ok" });
    expect(keys.statusCode).toBe(200);
    expect(keys.json()).toEqual(context.keyRegistry);
    await app.close();
  });

  it("returns policy BLOCK decisions with HTTP 200", async () => {
    const context = await testContext();
    const app = await buildDemoApi({ ...context, logger: false });
    const action = actionFromX402({
      ...bindingInput,
      paymentRequirements: { ...bindingInput.paymentRequirements, amount: "150000000" },
    });
    const response = await app.inject({
      method: "POST",
      url: "/v1/decisions/evaluate",
      payload: { action },
    });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      decision: {
        verdict: "BLOCK",
        reason_codes: ["AMOUNT_EXCEEDS_TRANSACTION_LIMIT"],
      },
    });
    await app.close();
  });

  it("verifies and consumes a decision with replay conflict semantics", async () => {
    const context = await testContext();
    const app = await buildDemoApi({ ...context, logger: false });
    const action = actionFromX402(bindingInput);
    const decision = await context.provider.evaluate(action);

    const verification = await app.inject({
      method: "POST",
      url: "/v1/decisions/verify",
      payload: { decision, action, expected_policy_version: "1" },
    });
    expect(verification.statusCode).toBe(200);
    expect(verification.json()).toMatchObject({ valid: true });

    const input = {
      decision_id: decision.decision_id,
      action_hash: decision.action_hash,
      execution_ref: "execution-A",
    };
    const first = await app.inject({
      method: "POST",
      url: "/v1/decisions/consume",
      payload: input,
    });
    const retry = await app.inject({
      method: "POST",
      url: "/v1/decisions/consume",
      payload: input,
    });
    const replay = await app.inject({
      method: "POST",
      url: "/v1/decisions/consume",
      payload: { ...input, execution_ref: "execution-B" },
    });
    expect(first.statusCode).toBe(200);
    expect(first.json()).toMatchObject({ status: "consumed" });
    expect(retry.statusCode).toBe(200);
    expect(retry.json()).toMatchObject({ status: "idempotent" });
    expect(replay.statusCode).toBe(409);
    expect(replay.json()).toMatchObject({ reason_code: "NONCE_ALREADY_CONSUMED" });
    await app.close();
  });

  it("resolves a human approval into a superseding decision", async () => {
    const context = await testContext();
    const app = await buildDemoApi({ ...context, logger: false });
    const action = actionFromX402({
      ...bindingInput,
      paymentRequirements: { ...bindingInput.paymentRequirements, amount: "80000000" },
    });
    const evaluated = await app.inject({
      method: "POST",
      url: "/v1/decisions/evaluate",
      payload: { action },
    });
    const pending = evaluated.json<{ decision: InntrisDecisionV1 }>().decision;
    expect(pending.verdict).toBe("REQUIRE_APPROVAL");

    const payload = {
      decision_id: pending.decision_id,
      granted: true,
      approval_reference: "approval-ticket-api",
      approver_ids: ["user_finance_lead"],
    };
    const approved = await app.inject({
      method: "POST",
      url: "/v1/decisions/approve",
      payload,
    });
    expect(approved.statusCode).toBe(200);
    expect(approved.json()).toMatchObject({
      success: true,
      status: "superseded",
      decision: {
        verdict: "ALLOW",
        supersedes_decision_id: pending.decision_id,
        approval: { mode: "human", approval_reference: "approval-ticket-api" },
      },
    });

    // The approval request is single use, so a repeat is a conflict.
    const replay = await app.inject({
      method: "POST",
      url: "/v1/decisions/approve",
      payload,
    });
    expect(replay.statusCode).toBe(409);
    expect(replay.json()).toMatchObject({ reason_code: "APPROVAL_ALREADY_RESOLVED" });

    // A decision that was never an open approval request cannot be resolved.
    const notPending = await app.inject({
      method: "POST",
      url: "/v1/decisions/approve",
      payload: {
        ...payload,
        decision_id: approved.json<{ decision: InntrisDecisionV1 }>().decision.decision_id,
      },
    });
    expect(notPending.statusCode).toBe(422);
    expect(notPending.json()).toMatchObject({ reason_code: "APPROVAL_NOT_PENDING" });
    await app.close();
  });

  it("supports optional bearer authentication without exposing the key", async () => {
    const context = await testContext();
    const app = await buildDemoApi({
      ...context,
      logger: false,
      serviceApiKey: "local-test-key",
    });
    const denied = await app.inject({
      method: "POST",
      url: "/v1/decisions/evaluate",
      payload: { action: actionFromX402(bindingInput) },
    });
    expect(denied.statusCode).toBe(401);
    expect(denied.body).not.toContain("local-test-key");
    await app.close();
  });

  it("rate limits repeated requests", async () => {
    const context = await testContext();
    const app = await buildDemoApi({ ...context, logger: false });
    let response;
    for (let requestNumber = 0; requestNumber <= 100; requestNumber += 1) {
      response = await app.inject({ method: "GET", url: "/healthz" });
    }
    expect(response?.statusCode).toBe(429);
    await app.close();
  });

  it("applies the stricter limit to decision endpoints", async () => {
    const context = await testContext();
    const app = await buildDemoApi({ ...context, logger: false });
    const action = actionFromX402(bindingInput);
    const decision = await context.provider.evaluate(action);
    let response;
    for (let requestNumber = 0; requestNumber <= 30; requestNumber += 1) {
      response = await app.inject({
        method: "POST",
        url: "/v1/decisions/verify",
        payload: { decision, action },
      });
    }
    expect(response?.statusCode).toBe(429);
    await app.close();
  });
});
