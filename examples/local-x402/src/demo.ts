import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import {
  buildKeyRegistryEntry,
  createPublicDemoSigner,
  type Clock,
  type InntrisDecisionV1,
} from "@inntris/decision-core";
import { LocalPolicyDecisionProvider, parsePolicyText } from "@inntris/policy-engine";
import {
  InntrisGuardError,
  InntrisX402Guard,
  type PaymentRequirements,
  type X402SettlementInput,
} from "@inntris/x402-adapter";

class MutableClock implements Clock {
  constructor(private value: Date) {}

  now(): Date {
    return new Date(this.value);
  }

  advance(milliseconds: number): void {
    this.value = new Date(this.value.getTime() + milliseconds);
  }
}

const baseRequirements: PaymentRequirements = {
  scheme: "exact",
  network: "eip155:8453",
  asset: "USDC",
  amount: "4500000",
  payTo: "0x0000000000000000000000000000000000000001",
  maxTimeoutSeconds: 60,
  extra: {},
};

const baseInput: X402SettlementInput = {
  paymentRequirements: baseRequirements,
  resource: "https://example.test/research",
  principalId: "org_demo",
  agentId: "agent_research_01",
  purpose: "research_api",
  assetDecimals: 6,
};

function inputWithAmount(amount: string): X402SettlementInput {
  return {
    ...baseInput,
    paymentRequirements: { ...baseRequirements, amount },
  };
}

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(`Demo assertion failed: ${message}`);
  }
}

async function expectBlocked(
  name: string,
  operation: () => Promise<unknown>,
  expectedReason: string,
): Promise<void> {
  try {
    await operation();
    throw new Error(`${name} unexpectedly permitted settlement`);
  } catch (error) {
    if (!(error instanceof InntrisGuardError)) {
      throw error;
    }
    assert(error.reasonCodes.includes(expectedReason as never), `${name} reason code`);
    process.stdout.write(`${name}: ${expectedReason}; settlement not called\n`);
  }
}

const clock = new MutableClock(new Date("2026-07-29T12:00:00.000Z"));
const signer = createPublicDemoSigner();
const policy = parsePolicyText(await readFile(resolve("policies/demo-x402-policy.yml"), "utf8"));
const provider = new LocalPolicyDecisionProvider({ policy, signer, clock });
const keyRegistry = {
  version: "inntris-key-registry-v1" as const,
  keys: [
    buildKeyRegistryEntry(signer, {
      notBefore: new Date("2026-01-01T00:00:00.000Z"),
    }),
  ],
};
const guard = new InntrisX402Guard({
  provider,
  keyRegistry,
  expectedPolicyVersion: "1",
  clock,
});

let settlementCalls = 0;
const settlement = async (): Promise<string> => {
  settlementCalls += 1;
  return "settled";
};

process.stdout.write("Inntris x402 policy adapter demonstration\n\n");

const allowed = await guard.authorise(baseInput);
assert(allowed.verdict === "ALLOW", "allowed scenario verdict");
await guard.settleIfAuthorised(baseInput, allowed, "execution-allow-A", settlement);
process.stdout.write(
  "Scenario 1: ALLOW; signature valid; decision consumed; settlement permitted\n",
);

const blocked = await guard.authorise(inputWithAmount("150000000"));
assert(blocked.verdict === "BLOCK", "blocked scenario verdict");
await expectBlocked(
  "Scenario 2",
  () =>
    guard.settleIfAuthorised(inputWithAmount("150000000"), blocked, "execution-block", settlement),
  "DECISION_NOT_ALLOW",
);
assert(
  blocked.reason_codes.includes("AMOUNT_EXCEEDS_TRANSACTION_LIMIT"),
  "blocked decision reason",
);

const approval = await guard.authorise(inputWithAmount("80000000"));
assert(approval.verdict === "REQUIRE_APPROVAL", "approval scenario verdict");
await expectBlocked(
  "Scenario 3",
  () =>
    guard.settleIfAuthorised(
      inputWithAmount("80000000"),
      approval,
      "execution-approval",
      settlement,
    ),
  "DECISION_NOT_ALLOW",
);
assert(approval.reason_codes.includes("HUMAN_APPROVAL_REQUIRED"), "approval reason");

const tamperDecision = await guard.authorise(baseInput);
const tamperedInput: X402SettlementInput = {
  ...baseInput,
  paymentRequirements: {
    ...baseRequirements,
    payTo: "0x0000000000000000000000000000000000000002",
  },
};
await expectBlocked(
  "Scenario 4",
  () => guard.settleIfAuthorised(tamperedInput, tamperDecision, "execution-tamper", settlement),
  "ACTION_HASH_MISMATCH",
);

const replayDecision: InntrisDecisionV1 = await guard.authorise(baseInput);
await guard.settleIfAuthorised(baseInput, replayDecision, "execution-replay-A", settlement);
await expectBlocked(
  "Scenario 5",
  () => guard.settleIfAuthorised(baseInput, replayDecision, "execution-replay-B", settlement),
  "NONCE_ALREADY_CONSUMED",
);

const expiringDecision = await guard.authorise(baseInput);
clock.advance(61_000);
await expectBlocked(
  "Scenario 6",
  () => guard.settleIfAuthorised(baseInput, expiringDecision, "execution-expired", settlement),
  "DECISION_EXPIRED",
);

assert(settlementCalls === 2, "only the two authorised unique executions settled");
process.stdout.write(`\nPASS: settlement called exactly ${settlementCalls} times\n`);
