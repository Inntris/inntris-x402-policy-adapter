import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { evaluatePolicy, InMemorySpendState, parsePolicyText } from "@inntris/policy-engine";
import { actionFromX402 } from "@inntris/x402-adapter";
import { describe, expect, it } from "vitest";

import { bindingInput, MutableClock, testContext } from "../helpers.js";

async function demoPolicy() {
  return parsePolicyText(await readFile(resolve("policies/demo-x402-policy.yml"), "utf8"));
}

describe("deterministic policy precedence", () => {
  it("blocks a daily cumulative limit breach", async () => {
    const spend = new InMemorySpendState();
    spend.setDailySpend("org_demo", "2026-07-29", "499.00");
    const result = await evaluatePolicy({
      action: actionFromX402(bindingInput),
      policy: await demoPolicy(),
      spendState: spend,
      clock: new MutableClock(),
    });
    expect(result).toMatchObject({
      verdict: "BLOCK",
      reasonCodes: ["DAILY_LIMIT_EXCEEDED"],
    });
  });

  it("blocks outside the configured time window", async () => {
    const result = await evaluatePolicy({
      action: actionFromX402(bindingInput),
      policy: await demoPolicy(),
      spendState: new InMemorySpendState(),
      clock: new MutableClock(new Date("2026-07-29T23:00:00.000Z")),
    });
    expect(result).toMatchObject({
      verdict: "BLOCK",
      reasonCodes: ["OUTSIDE_ALLOWED_TIME"],
    });
  });

  it("accumulates cumulative spend when a decision is consumed", async () => {
    const spend = new InMemorySpendState();
    const context = await testContext(new MutableClock(), { spendState: spend });
    const decision = await context.provider.evaluate(actionFromX402(bindingInput));

    expect(await spend.getDailySpend("org_demo", "2026-07-29")).toBe("0.00");
    await context.provider.consume({
      decision_id: decision.decision_id,
      action_hash: decision.action_hash,
      execution_ref: "execution-a",
    });
    expect(await spend.getDailySpend("org_demo", "2026-07-29")).toBe("4.50");

    // An idempotent retry of the same execution must not be counted twice.
    await context.provider.consume({
      decision_id: decision.decision_id,
      action_hash: decision.action_hash,
      execution_ref: "execution-a",
    });
    expect(await spend.getDailySpend("org_demo", "2026-07-29")).toBe("4.50");

    const second = await context.provider.evaluate(actionFromX402(bindingInput));
    await context.provider.consume({
      decision_id: second.decision_id,
      action_hash: second.action_hash,
      execution_ref: "execution-b",
    });
    expect(await spend.getDailySpend("org_demo", "2026-07-29")).toBe("9.00");
  });

  it("blocks once accumulated consumption breaches the daily limit", async () => {
    const spend = new InMemorySpendState();
    // 491.50 + 4.50 stays inside the 500.00 daily limit; a second 4.50 does not.
    spend.setDailySpend("org_demo", "2026-07-29", "491.50");
    const context = await testContext(new MutableClock(), { spendState: spend });

    const first = await context.provider.evaluate(actionFromX402(bindingInput));
    expect(first.verdict).toBe("ALLOW");
    await context.provider.consume({
      decision_id: first.decision_id,
      action_hash: first.action_hash,
      execution_ref: "execution-a",
    });

    const second = await context.provider.evaluate(actionFromX402(bindingInput));
    expect(second.verdict).toBe("BLOCK");
    expect(second.reason_codes).toEqual(["DAILY_LIMIT_EXCEEDED"]);
  });

  it("supports a time window that crosses local midnight", async () => {
    const policy = await demoPolicy();
    const overnight = {
      ...policy,
      time_windows: {
        ...policy.time_windows,
        allowed_weekdays: [...policy.time_windows.allowed_weekdays, "SATURDAY" as const],
        start: "22:00",
        end: "02:00",
      },
    };
    const at = async (timestamp: string) =>
      evaluatePolicy({
        action: actionFromX402(bindingInput),
        policy: overnight,
        spendState: new InMemorySpendState(),
        clock: new MutableClock(new Date(timestamp)),
      });

    // 2026-07-29 is a Wednesday, so 23:00 and the following 01:00 are both inside.
    expect(await at("2026-07-29T23:00:00.000Z")).toMatchObject({ verdict: "ALLOW" });
    expect(await at("2026-07-30T01:00:00.000Z")).toMatchObject({ verdict: "ALLOW" });
    expect(await at("2026-07-29T12:00:00.000Z")).toMatchObject({
      verdict: "BLOCK",
      reasonCodes: ["OUTSIDE_ALLOWED_TIME"],
    });
  });

  it("applies explicit deny before a human approval threshold", async () => {
    const policy = await demoPolicy();
    const result = await evaluatePolicy({
      action: actionFromX402({
        ...bindingInput,
        paymentRequirements: { ...bindingInput.paymentRequirements, amount: "80000000" },
      }),
      policy: {
        ...policy,
        deny: {
          networks: [],
          assets: [],
          payees: [bindingInput.paymentRequirements.payTo],
          resources: [],
          purposes: [],
        },
      },
      spendState: new InMemorySpendState(),
      clock: new MutableClock(),
    });
    expect(result).toMatchObject({
      verdict: "BLOCK",
      reasonCodes: ["PAYEE_NOT_ALLOWED"],
    });
  });
});
