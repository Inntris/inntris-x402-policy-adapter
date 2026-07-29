import {
  InntrisX402Guard,
  remoteProviderFromEnvironment,
  type PaymentRequirements,
} from "@inntris/x402-adapter";

const provider = await remoteProviderFromEnvironment();
const requirements: PaymentRequirements = {
  scheme: "exact",
  network: "eip155:8453",
  asset: "USDC",
  amount: "4500000",
  payTo: "0x0000000000000000000000000000000000000001",
  maxTimeoutSeconds: 60,
  extra: {},
};
const guard = new InntrisX402Guard({
  provider,
  keyRegistry: provider.options.keyRegistry,
  expectedPolicyVersion: provider.options.expectedPolicyVersion,
});

const decision = await guard.authorise({
  paymentRequirements: requirements,
  resource: "https://example.test/research",
  principalId: "org_demo",
  agentId: "agent_research_01",
  purpose: "research_api",
  assetDecimals: 6,
});

process.stdout.write(`${decision.verdict} ${decision.decision_id}\n`);
