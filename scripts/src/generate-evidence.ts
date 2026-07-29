import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

import {
  buildKeyRegistryEntry,
  createPublicDemoSigner,
  createSignedDecision,
  hashPolicyObject,
  type Clock,
  type InntrisActionV1,
  type InntrisDecisionV1,
  type ReasonCode,
} from "@inntris/decision-core";
import { evaluatePolicy, parsePolicyText, ZeroSpendState } from "@inntris/policy-engine";
import {
  actionFromX402,
  paymentRequirementsHash,
  type PaymentRequirements,
} from "@inntris/x402-adapter";
import { format } from "prettier";

interface FixtureExpectation {
  verification_valid: boolean;
  reason_code: ReasonCode | null;
  settlement_may_proceed: boolean;
}

interface DecisionFixture {
  name: string;
  decision: InntrisDecisionV1 | Record<string, unknown>;
  action: InntrisActionV1;
  expected: FixtureExpectation;
  expected_policy_version?: string;
  expected_payment_requirements_hash?: string;
}

class FixedClock implements Clock {
  constructor(private readonly at: Date) {}
  now(): Date {
    return new Date(this.at);
  }
}

const root = resolve(".");
const policy = parsePolicyText(
  await readFile(resolve(root, "policies/demo-x402-policy.yml"), "utf8"),
);
const policyHash = hashPolicyObject(policy);
const signer = createPublicDemoSigner();
const issuedAt = new Date("2026-07-29T09:30:00.000Z");
const clock = new FixedClock(issuedAt);
const requirements: PaymentRequirements = {
  scheme: "exact",
  network: "eip155:8453",
  asset: "USDC",
  amount: "4500000",
  payTo: "0x0000000000000000000000000000000000000001",
  maxTimeoutSeconds: 60,
  extra: {},
};
const action = actionFromX402({
  paymentRequirements: requirements,
  resource: "https://example.test/research",
  principalId: "org_demo",
  agentId: "agent_research_01",
  purpose: "research_api",
  assetDecimals: 6,
});

async function signedDecision(
  fixtureAction: InntrisActionV1,
  options: {
    id: string;
    nonce: string;
    ttl?: number;
    policyVersion?: string;
  },
): Promise<InntrisDecisionV1> {
  const evaluation = await evaluatePolicy({
    action: fixtureAction,
    policy,
    spendState: new ZeroSpendState(),
    clock,
  });
  return createSignedDecision({
    action: fixtureAction,
    evaluation,
    policyHash,
    policyVersion: options.policyVersion ?? policy.policy_version,
    decisionTtlSeconds: options.ttl ?? policy.defaults.decision_ttl_seconds,
    signer,
    clock,
    decisionId: options.id,
    nonce: options.nonce,
  });
}

const allow = await signedDecision(action, {
  id: "018f0000-0000-7000-8000-000000000001",
  nonce: "Zml4dHVyZS1ub25jZS1hbGxvdw",
});
const blockAction = actionFromX402({
  paymentRequirements: { ...requirements, amount: "150000000" },
  resource: "https://example.test/research",
  principalId: "org_demo",
  agentId: "agent_research_01",
  purpose: "research_api",
  assetDecimals: 6,
});
const block = await signedDecision(blockAction, {
  id: "018f0000-0000-7000-8000-000000000002",
  nonce: "Zml4dHVyZS1ub25jZS1ibG9jaw",
});
const approvalAction = actionFromX402({
  paymentRequirements: { ...requirements, amount: "80000000" },
  resource: "https://example.test/research",
  principalId: "org_demo",
  agentId: "agent_research_01",
  purpose: "research_api",
  assetDecimals: 6,
});
const requireApproval = await signedDecision(approvalAction, {
  id: "018f0000-0000-7000-8000-000000000003",
  nonce: "Zml4dHVyZS1ub25jZS1hcHByb3ZhbA",
});
const expired = await signedDecision(action, {
  id: "018f0000-0000-7000-8000-000000000004",
  nonce: "Zml4dHVyZS1ub25jZS1leHBpcmVk",
  ttl: 1,
});
const stale = await signedDecision(action, {
  id: "018f0000-0000-7000-8000-000000000005",
  nonce: "Zml4dHVyZS1ub25jZS1zdGFsZQ",
  policyVersion: "0",
});

function mutateDecision(
  decision: InntrisDecisionV1,
  mutation: (copy: Record<string, unknown>) => void,
): Record<string, unknown> {
  const copy = structuredClone(decision) as unknown as Record<string, unknown>;
  mutation(copy);
  return copy;
}

function actionMutation(mutation: (copy: InntrisActionV1) => void): InntrisActionV1 {
  const copy = structuredClone(action);
  mutation(copy);
  return copy;
}

const tamperedRequirements = { ...requirements, amount: "5500000" };
const fixtures: DecisionFixture[] = [
  {
    name: "valid-allow",
    decision: allow,
    action,
    expected: { verification_valid: true, reason_code: null, settlement_may_proceed: true },
  },
  {
    name: "valid-block",
    decision: block,
    action: blockAction,
    expected: {
      verification_valid: true,
      reason_code: "DECISION_NOT_ALLOW",
      settlement_may_proceed: false,
    },
  },
  {
    name: "valid-require-approval",
    decision: requireApproval,
    action: approvalAction,
    expected: {
      verification_valid: true,
      reason_code: "DECISION_NOT_ALLOW",
      settlement_may_proceed: false,
    },
  },
  {
    name: "tampered-verdict",
    decision: mutateDecision(allow, (copy) => {
      copy.verdict = "BLOCK";
    }),
    action,
    expected: {
      verification_valid: false,
      reason_code: "FINGERPRINT_MISMATCH",
      settlement_may_proceed: false,
    },
  },
  {
    name: "tampered-amount",
    decision: allow,
    action: actionMutation((copy) => {
      copy.transaction.amount = "5.50";
    }),
    expected: {
      verification_valid: false,
      reason_code: "ACTION_HASH_MISMATCH",
      settlement_may_proceed: false,
    },
  },
  {
    name: "tampered-payee",
    decision: allow,
    action: actionMutation((copy) => {
      copy.transaction.payee = "0x0000000000000000000000000000000000000002";
    }),
    expected: {
      verification_valid: false,
      reason_code: "ACTION_HASH_MISMATCH",
      settlement_may_proceed: false,
    },
  },
  {
    name: "tampered-network",
    decision: allow,
    action: actionMutation((copy) => {
      copy.transaction.network = "eip155:1";
    }),
    expected: {
      verification_valid: false,
      reason_code: "ACTION_HASH_MISMATCH",
      settlement_may_proceed: false,
    },
  },
  {
    name: "tampered-policy-hash",
    decision: mutateDecision(allow, (copy) => {
      copy.policy = {
        policy_hash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        policy_version: "1",
      };
    }),
    action,
    expected: {
      verification_valid: false,
      reason_code: "FINGERPRINT_MISMATCH",
      settlement_may_proceed: false,
    },
  },
  {
    name: "unknown-signing-key",
    decision: mutateDecision(allow, (copy) => {
      const signing = copy.signing as Record<string, unknown>;
      signing.key_id = "unknown-key";
    }),
    action,
    expected: {
      verification_valid: false,
      reason_code: "UNKNOWN_SIGNING_KEY",
      settlement_may_proceed: false,
    },
  },
  {
    name: "expired-decision",
    decision: expired,
    action,
    expected: {
      verification_valid: false,
      reason_code: "DECISION_EXPIRED",
      settlement_may_proceed: false,
    },
  },
  {
    name: "stale-policy-version",
    decision: stale,
    action,
    expected: {
      verification_valid: false,
      reason_code: "POLICY_VERSION_MISMATCH",
      settlement_may_proceed: false,
    },
    expected_policy_version: "1",
  },
  {
    name: "replayed-decision",
    decision: allow,
    action,
    expected: {
      verification_valid: true,
      reason_code: "NONCE_ALREADY_CONSUMED",
      settlement_may_proceed: false,
    },
  },
  {
    name: "x402-challenge-mismatch",
    decision: allow,
    action,
    expected: {
      verification_valid: false,
      reason_code: "PAYMENT_REQUIREMENTS_MISMATCH",
      settlement_may_proceed: false,
    },
    expected_payment_requirements_hash: paymentRequirementsHash(tamperedRequirements),
  },
];

async function writeJson(path: string, value: unknown): Promise<void> {
  await mkdir(resolve(path, ".."), { recursive: true });
  await writeFile(
    path,
    await format(JSON.stringify(value), { parser: "json", printWidth: 100 }),
    "utf8",
  );
}

await writeJson(resolve(root, "fixtures/actions/allow.json"), action);
await writeJson(resolve(root, "fixtures/actions/block.json"), blockAction);
await writeJson(resolve(root, "fixtures/actions/require-approval.json"), approvalAction);
await writeJson(resolve(root, "fixtures/policies/demo.json"), policy);
await writeJson(resolve(root, "fixtures/keys/registry.json"), {
  version: "inntris-key-registry-v1",
  keys: [
    buildKeyRegistryEntry(signer, {
      notBefore: new Date("2026-01-01T00:00:00.000Z"),
    }),
  ],
});
for (const fixture of fixtures) {
  await writeJson(resolve(root, `fixtures/decisions/${fixture.name}.json`), fixture);
}
await writeJson(
  resolve(root, "fixtures/manifest.json"),
  fixtures.map(({ name, expected }) => ({ name, expected })),
);
await writeJson(resolve(root, "evidence/allow.json"), allow);
await writeJson(resolve(root, "evidence/action.json"), action);

process.stdout.write(`Generated ${fixtures.length} decision vectors and public ALLOW evidence\n`);
