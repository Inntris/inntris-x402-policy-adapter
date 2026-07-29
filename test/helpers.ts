import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import {
  buildKeyRegistryEntry,
  createPublicDemoSigner,
  type Clock,
  type KeyRegistry,
} from "@inntris/decision-core";
import { LocalPolicyDecisionProvider, parsePolicyText } from "@inntris/policy-engine";
import {
  InntrisX402Guard,
  type PaymentRequirements,
  type X402SettlementInput,
} from "@inntris/x402-adapter";

export class MutableClock implements Clock {
  constructor(private value: Date = new Date("2026-07-29T12:00:00.000Z")) {}

  now(): Date {
    return new Date(this.value);
  }

  advance(milliseconds: number): void {
    this.value = new Date(this.value.getTime() + milliseconds);
  }
}

export const requirements: PaymentRequirements = {
  scheme: "exact",
  network: "eip155:8453",
  asset: "USDC",
  amount: "4500000",
  payTo: "0x0000000000000000000000000000000000000001",
  maxTimeoutSeconds: 60,
  extra: {},
};

export const bindingInput: X402SettlementInput = {
  paymentRequirements: requirements,
  resource: "https://example.test/research",
  principalId: "org_demo",
  agentId: "agent_research_01",
  purpose: "research_api",
  assetDecimals: 6,
};

export async function testContext(clock = new MutableClock()): Promise<{
  clock: MutableClock;
  provider: LocalPolicyDecisionProvider;
  guard: InntrisX402Guard;
  keyRegistry: KeyRegistry;
}> {
  const policy = parsePolicyText(await readFile(resolve("policies/demo-x402-policy.yml"), "utf8"));
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
  return {
    clock,
    provider,
    keyRegistry,
    guard: new InntrisX402Guard({
      provider,
      keyRegistry,
      expectedPolicyVersion: "1",
      clock,
    }),
  };
}
