import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { createPublicDemoSigner } from "@inntris/decision-core";
import { verifyDecision } from "@inntris/decision-verifier";
import {
  InMemoryDecisionStateStore,
  InMemorySpendState,
  LocalPolicyDecisionProvider,
  parsePolicyText,
} from "@inntris/policy-engine";
import { actionFromX402 } from "@inntris/x402-adapter";
import { describe, expect, it } from "vitest";

import { bindingInput, MutableClock, testContext } from "../helpers.js";

const approvalInput = {
  ...bindingInput,
  paymentRequirements: { ...bindingInput.paymentRequirements, amount: "80000000" },
};

async function pendingApproval(clock = new MutableClock()) {
  const context = await testContext(clock);
  const decision = await context.provider.evaluate(actionFromX402(approvalInput));
  expect(decision.verdict).toBe("REQUIRE_APPROVAL");
  return { ...context, decision };
}

describe("human approval supersession", () => {
  it("issues a new ALLOW decision without mutating the approval request", async () => {
    const { provider, decision, keyRegistry, clock } = await pendingApproval();
    const original = structuredClone(decision);

    const result = await provider.resolveApproval({
      decision_id: decision.decision_id,
      granted: true,
      approval_reference: "approval-ticket-1",
      approver_ids: ["user_finance_lead"],
    });

    expect(result).toMatchObject({ success: true, status: "superseded" });
    const superseding = result.decision!;
    expect(superseding.verdict).toBe("ALLOW");
    expect(superseding.supersedes_decision_id).toBe(decision.decision_id);
    expect(superseding.decision_id).not.toBe(decision.decision_id);
    expect(superseding.nonce).not.toBe(decision.nonce);
    expect(superseding.action_hash).toBe(decision.action_hash);
    expect(superseding.approval).toEqual({
      mode: "human",
      approval_reference: "approval-ticket-1",
      approver_ids: ["user_finance_lead"],
    });
    expect(superseding.reason_codes).toContain("HUMAN_APPROVAL_GRANTED");
    expect(superseding.reason_codes).not.toContain("HUMAN_APPROVAL_REQUIRED");

    // The original REQUIRE_APPROVAL decision is byte-for-byte unchanged.
    expect(decision).toEqual(original);

    const verification = verifyDecision({
      decision: superseding,
      action: actionFromX402(approvalInput),
      keyRegistry,
      at: clock.now(),
      expectedPolicyVersion: "1",
    });
    expect(verification.valid).toBe(true);
  });

  it("lets the superseding decision authorise exactly one execution", async () => {
    const { provider, decision } = await pendingApproval();
    const result = await provider.resolveApproval({
      decision_id: decision.decision_id,
      granted: true,
      approval_reference: "approval-ticket-2",
      approver_ids: ["user_finance_lead"],
    });
    const superseding = result.decision!;

    const first = await provider.consume({
      decision_id: superseding.decision_id,
      action_hash: superseding.action_hash,
      execution_ref: "execution-a",
    });
    const replay = await provider.consume({
      decision_id: superseding.decision_id,
      action_hash: superseding.action_hash,
      execution_ref: "execution-b",
    });

    expect(first).toMatchObject({ success: true, status: "consumed" });
    expect(replay).toMatchObject({
      success: false,
      status: "conflict",
      reason_code: "NONCE_ALREADY_CONSUMED",
    });
  });

  it("signs a BLOCK decision when the approval is refused", async () => {
    const { provider, decision } = await pendingApproval();
    const result = await provider.resolveApproval({
      decision_id: decision.decision_id,
      granted: false,
      approval_reference: "approval-ticket-3",
      approver_ids: ["user_finance_lead"],
    });
    const superseding = result.decision!;

    expect(result.success).toBe(true);
    expect(superseding.verdict).toBe("BLOCK");
    expect(superseding.reason_codes).toEqual(["HUMAN_APPROVAL_REFUSED"]);

    const consumption = await provider.consume({
      decision_id: superseding.decision_id,
      action_hash: superseding.action_hash,
      execution_ref: "execution-refused",
    });
    expect(consumption).toMatchObject({ success: false, reason_code: "DECISION_NOT_ALLOW" });
  });

  it("refuses a second resolution of the same approval request", async () => {
    const { provider, decision } = await pendingApproval();
    const input = {
      decision_id: decision.decision_id,
      granted: true,
      approval_reference: "approval-ticket-4",
      approver_ids: ["user_finance_lead"],
    };
    await provider.resolveApproval(input);
    const replay = await provider.resolveApproval(input);

    expect(replay).toMatchObject({
      success: false,
      status: "conflict",
      reason_code: "APPROVAL_ALREADY_RESOLVED",
    });
    expect(replay.decision).toBeUndefined();
  });

  it("atomically accepts only one concurrent resolution across provider instances", async () => {
    const clock = new MutableClock();
    const decisionStore = new InMemoryDecisionStateStore();
    const first = await testContext(clock, { decisionStore });
    const secondProvider = new LocalPolicyDecisionProvider({
      ...first.provider.options,
      decisionStore,
    });
    const decision = await first.provider.evaluate(actionFromX402(approvalInput));

    const results = await Promise.all([
      first.provider.resolveApproval({
        decision_id: decision.decision_id,
        granted: true,
        approval_reference: "approval-ticket-concurrent-a",
        approver_ids: ["user_finance_lead"],
      }),
      secondProvider.resolveApproval({
        decision_id: decision.decision_id,
        granted: true,
        approval_reference: "approval-ticket-concurrent-b",
        approver_ids: ["user_finance_lead"],
      }),
    ]);

    expect(results.filter((result) => result.success)).toHaveLength(1);
    expect(results.filter((result) => !result.success)).toEqual([
      expect.objectContaining({
        status: "conflict",
        reason_code: "APPROVAL_ALREADY_RESOLVED",
      }),
    ]);
  });

  it("refuses to resolve an approval request after its window closes", async () => {
    const clock = new MutableClock();
    const { provider, decision } = await pendingApproval(clock);
    clock.advance(901_000);

    const result = await provider.resolveApproval({
      decision_id: decision.decision_id,
      granted: true,
      approval_reference: "approval-ticket-5",
      approver_ids: ["user_finance_lead"],
    });

    expect(result).toMatchObject({
      success: false,
      status: "rejected",
      reason_code: "DECISION_EXPIRED",
    });
  });

  it("honours an explicit approval request window from the policy", async () => {
    const clock = new MutableClock();
    const source = await readFile(resolve("policies/demo-x402-policy.yml"), "utf8");
    const policy = parsePolicyText(
      source.replace(
        'require_human_above: "75.00"',
        'require_human_above: "75.00"\n  request_ttl_seconds: 120',
      ),
    );
    expect(policy.approval.request_ttl_seconds).toBe(120);
    const provider = new LocalPolicyDecisionProvider({
      policy,
      signer: createPublicDemoSigner(),
      clock,
    });
    const decision = await provider.evaluate(actionFromX402(approvalInput));
    clock.advance(121_000);

    const result = await provider.resolveApproval({
      decision_id: decision.decision_id,
      granted: true,
      approval_reference: "approval-ticket-6",
      approver_ids: ["user_finance_lead"],
    });
    expect(result).toMatchObject({ success: false, reason_code: "DECISION_EXPIRED" });
  });

  it("refuses to resolve a decision that is not an open approval request", async () => {
    const context = await testContext();
    const allow = await context.provider.evaluate(actionFromX402(bindingInput));
    expect(allow.verdict).toBe("ALLOW");

    const onAllow = await context.provider.resolveApproval({
      decision_id: allow.decision_id,
      granted: true,
      approval_reference: "approval-ticket-7",
      approver_ids: ["user_finance_lead"],
    });
    const onUnknown = await context.provider.resolveApproval({
      decision_id: "018f0000-0000-7000-8000-00000000ffff",
      granted: true,
      approval_reference: "approval-ticket-8",
      approver_ids: ["user_finance_lead"],
    });

    expect(onAllow).toMatchObject({ success: false, reason_code: "APPROVAL_NOT_PENDING" });
    expect(onUnknown).toMatchObject({ success: false, reason_code: "APPROVAL_NOT_PENDING" });
  });

  it("lets current policy override a granted approval", async () => {
    const clock = new MutableClock();
    const policy = parsePolicyText(
      await readFile(resolve("policies/demo-x402-policy.yml"), "utf8"),
    );
    const spendState = new InMemorySpendState();
    const provider = new LocalPolicyDecisionProvider({
      policy,
      signer: createPublicDemoSigner(),
      clock,
      spendState,
    });
    const decision = await provider.evaluate(actionFromX402(approvalInput));
    expect(decision.verdict).toBe("REQUIRE_APPROVAL");

    // Organisational state moves against the payment while the human deliberates.
    spendState.setDailySpend("org_demo", "2026-07-29", "450.00");

    const result = await provider.resolveApproval({
      decision_id: decision.decision_id,
      granted: true,
      approval_reference: "approval-ticket-9",
      approver_ids: ["user_finance_lead"],
    });
    const superseding = result.decision!;

    expect(superseding.verdict).toBe("BLOCK");
    expect(superseding.reason_codes).toEqual(["DAILY_LIMIT_EXCEEDED"]);
    expect(superseding.approval.mode).toBe("human");
  });
});
