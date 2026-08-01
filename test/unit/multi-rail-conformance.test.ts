import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import {
  buildKeyRegistryEntry,
  createPublicDemoSigner,
  hashAction,
  type KeyRegistry,
} from "@inntris/decision-core";
import {
  MockCardAuthorisationInputSchema,
  actionFromMockCardAuthorisation,
  actionFromPaidMcpToolCall,
  createPublicConformanceCases,
  runMultiRailConformance,
} from "@inntris/multi-rail-conformance";
import { LocalPolicyDecisionProvider, parsePolicyText } from "@inntris/policy-engine";
import { describe, expect, it } from "vitest";

import { MutableClock } from "../helpers.js";

async function conformanceContext() {
  const clock = new MutableClock();
  const policy = parsePolicyText(
    await readFile(resolve("policies/multi-rail-conformance.yml"), "utf8"),
  );
  const signer = createPublicDemoSigner();
  const keyRegistry: KeyRegistry = {
    version: "inntris-key-registry-v1",
    keys: [
      buildKeyRegistryEntry(signer, {
        notBefore: new Date("2026-01-01T00:00:00.000Z"),
      }),
    ],
  };
  const provider = new LocalPolicyDecisionProvider({ policy, signer, clock });
  return { clock, policy, provider, keyRegistry };
}

describe("multi-rail conformance", () => {
  it("runs one shared policy through five Decision Envelope variants", async () => {
    const context = await conformanceContext();

    const report = await runMultiRailConformance({
      cases: createPublicConformanceCases(),
      provider: context.provider,
      keyRegistry: context.keyRegistry,
      expectedPolicyVersion: context.policy.policy_version,
      clock: context.clock,
    });

    expect(report.passed).toBe(true);
    expect(report.outcomes.map((outcome) => outcome.rail)).toEqual([
      "x402",
      "ap2",
      "evm",
      "card",
      "mcp",
    ]);
    expect(new Set(report.outcomes.map((outcome) => outcome.decision.policy.policy_hash))).toEqual(
      new Set([report.policy_hash]),
    );
    expect(new Set(report.outcomes.map((outcome) => outcome.decision.signing.key_id))).toEqual(
      new Set([report.signing_key_id]),
    );
  });

  it("verifies every rail offline and rejects every exact action mutation", async () => {
    const context = await conformanceContext();
    const report = await runMultiRailConformance({
      cases: createPublicConformanceCases(),
      provider: context.provider,
      keyRegistry: context.keyRegistry,
      expectedPolicyVersion: context.policy.policy_version,
      clock: context.clock,
    });

    for (const outcome of report.outcomes) {
      expect(outcome.verification.valid).toBe(true);
      expect(outcome.mutationVerification.valid).toBe(false);
      expect(outcome.mutationVerification.reason_codes).toContain("ACTION_HASH_MISMATCH");
    }
  });

  it("requires exactly one case for each conformance rail", async () => {
    const context = await conformanceContext();
    const cases = createPublicConformanceCases();

    await expect(
      runMultiRailConformance({
        cases: cases.slice(0, -1),
        provider: context.provider,
        keyRegistry: context.keyRegistry,
        expectedPolicyVersion: context.policy.policy_version,
        clock: context.clock,
      }),
    ).rejects.toMatchObject({ name: "MultiRailConformanceError" });
  });

  it("hashes an opaque card credential without placing it in the action", () => {
    const base = {
      version: "inntris-mock-card-authorisation-v1",
      authorisationRequestId: "card-request-test",
      principalId: "org_conformance",
      agentId: "agent_conformance_01",
      resource: "https://card.example.test/authorise",
      purpose: "research_api",
      amount: "4.50",
      asset: "USD",
      merchantId: "merchant-card-demo",
      cardNetwork: "visa",
      credentialReference: "opaque-token-a",
    } as const;
    const first = actionFromMockCardAuthorisation(base);
    const second = actionFromMockCardAuthorisation({
      ...base,
      credentialReference: "opaque-token-b",
    });

    expect(JSON.stringify(first)).not.toContain("opaque-token-a");
    expect(hashAction(first)).not.toBe(hashAction(second));
  });

  it("hashes MCP tool arguments without copying them into the action", () => {
    const base = {
      version: "inntris-paid-mcp-tool-call-v1",
      toolCallId: "tool-call-test",
      principalId: "org_conformance",
      agentId: "agent_conformance_01",
      resource: "https://mcp.example.test/tools/research",
      purpose: "research_api",
      amount: "4.50",
      asset: "USD",
      serverId: "mcp-research-server",
      toolName: "paid_research",
      arguments: { query: "confidential query", limit: 5 },
      paymentReference: "mcp-payment-test",
    } as const;
    const first = actionFromPaidMcpToolCall(base);
    const second = actionFromPaidMcpToolCall({
      ...base,
      arguments: { ...base.arguments, limit: 6 },
    });

    expect(JSON.stringify(first)).not.toContain("confidential query");
    expect(hashAction(first)).not.toBe(hashAction(second));
  });

  it("rejects unversioned card fields such as a raw PAN", () => {
    expect(
      MockCardAuthorisationInputSchema.safeParse({
        version: "inntris-mock-card-authorisation-v1",
        authorisationRequestId: "card-request-test",
        principalId: "org_conformance",
        agentId: "agent_conformance_01",
        resource: "https://card.example.test/authorise",
        purpose: "research_api",
        amount: "4.50",
        asset: "USD",
        merchantId: "merchant-card-demo",
        cardNetwork: "visa",
        credentialReference: "opaque-token",
        raw_pan: "not-accepted",
      }).success,
    ).toBe(false);
  });
});
