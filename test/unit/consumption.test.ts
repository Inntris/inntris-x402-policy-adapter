import { describe, expect, it } from "vitest";

import { bindingInput, testContext } from "../helpers.js";

describe("single-use consumption", () => {
  it("succeeds once and makes the same execution retry idempotent", async () => {
    const context = await testContext();
    const decision = await context.guard.authorise(bindingInput);
    const first = await context.guard.consumeBeforeExecution(decision, "execution-A");
    const retry = await context.guard.consumeBeforeExecution(decision, "execution-A");
    expect(first).toMatchObject({ success: true, status: "consumed" });
    expect(retry).toMatchObject({ success: true, status: "idempotent" });
    expect(retry.consumed_at).toBe(first.consumed_at);
  });

  it("rejects a different execution reference as replay", async () => {
    const context = await testContext();
    const decision = await context.guard.authorise(bindingInput);
    await context.guard.consumeBeforeExecution(decision, "execution-A");
    const replay = await context.guard.consumeBeforeExecution(decision, "execution-B");
    expect(replay).toMatchObject({
      success: false,
      status: "conflict",
      reason_code: "NONCE_ALREADY_CONSUMED",
    });
  });
});
