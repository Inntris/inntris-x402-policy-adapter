import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import {
  CanonicalAmountSchema,
  InntrisActionV1Schema,
  hashAction,
  hashPolicyObject,
} from "@inntris/decision-core";
import { parsePolicyText } from "@inntris/policy-engine";
import { actionFromX402 } from "@inntris/x402-adapter";
import { describe, expect, it } from "vitest";

import { bindingInput } from "../helpers.js";

describe("canonical action and policy hashing", () => {
  it("ignores JSON key order", () => {
    const action = actionFromX402(bindingInput);
    const reordered = InntrisActionV1Schema.parse({
      rail: action.rail,
      action_type: action.action_type,
      agent_id: action.agent_id,
      principal_id: action.principal_id,
      version: action.version,
      protocol_reference: {
        scheme: action.protocol_reference.scheme,
        resource: action.protocol_reference.resource,
        type: action.protocol_reference.type,
        payment_payload_hash: action.protocol_reference.payment_payload_hash,
        payment_requirements_hash: action.protocol_reference.payment_requirements_hash,
      },
      transaction: {
        purpose: action.transaction.purpose,
        payee: action.transaction.payee,
        network: action.transaction.network,
        asset: action.transaction.asset,
        amount: action.transaction.amount,
      },
    });
    expect(hashAction(reordered)).toBe(hashAction(action));
  });

  it("ignores JSON whitespace", () => {
    const action = actionFromX402(bindingInput);
    const compact = InntrisActionV1Schema.parse(JSON.parse(JSON.stringify(action)));
    const spaced = InntrisActionV1Schema.parse(JSON.parse(JSON.stringify(action, null, 4)));
    expect(hashAction(compact)).toBe(hashAction(spaced));
  });

  it("rejects 4.5 and accepts canonical 4.50", () => {
    expect(CanonicalAmountSchema.safeParse("4.50").success).toBe(true);
    expect(CanonicalAmountSchema.safeParse("4.5").success).toBe(false);
    expect(CanonicalAmountSchema.safeParse("4.500").success).toBe(false);
  });

  it.each([
    ["amount", (value: ReturnType<typeof actionFromX402>) => (value.transaction.amount = "5.50")],
    [
      "payee",
      (value: ReturnType<typeof actionFromX402>) =>
        (value.transaction.payee = "0x0000000000000000000000000000000000000002"),
    ],
    [
      "network",
      (value: ReturnType<typeof actionFromX402>) => (value.transaction.network = "eip155:1"),
    ],
    [
      "purpose",
      (value: ReturnType<typeof actionFromX402>) => (value.transaction.purpose = "other"),
    ],
  ])("changes the action hash when %s changes", (_name, mutate) => {
    const original = actionFromX402(bindingInput);
    const changed = structuredClone(original);
    mutate(changed);
    expect(hashAction(changed)).not.toBe(hashAction(original));
  });

  it("hashes policy meaning rather than YAML formatting", async () => {
    const source = await readFile(resolve("policies/demo-x402-policy.yml"), "utf8");
    const policy = parsePolicyText(source);
    const reformatted = parsePolicyText(JSON.stringify(policy, null, 4));
    expect(hashPolicyObject(reformatted)).toBe(hashPolicyObject(policy));
  });

  it("changes the policy hash for a semantic change", async () => {
    const source = await readFile(resolve("policies/demo-x402-policy.yml"), "utf8");
    const policy = parsePolicyText(source);
    const changed = structuredClone(policy);
    changed.limits.daily = "501.00";
    expect(hashPolicyObject(changed)).not.toBe(hashPolicyObject(policy));
  });
});
