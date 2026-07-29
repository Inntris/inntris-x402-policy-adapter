import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { evaluatePolicy, InMemorySpendState, parsePolicyText } from "@inntris/policy-engine";
import { actionFromX402 } from "@inntris/x402-adapter";
import { describe, expect, it } from "vitest";

import { bindingInput, MutableClock } from "../helpers.js";

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
