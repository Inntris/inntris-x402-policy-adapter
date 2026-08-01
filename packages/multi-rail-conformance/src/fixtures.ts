import {
  AP2_OFFICIAL_REPOSITORY,
  AP2_OFFICIAL_SDK_COMMIT,
  AP2_PROTOCOL_VERSION,
  actionFromAP2,
  type AP2OfficialVerification,
  type AP2RuntimeGateInput,
} from "@inntris/ap2-runtime-gate";
import { actionFromEvmTransaction, type EvmWalletGateInput } from "@inntris/wallet-signing-gate";
import { actionFromX402, type X402BindingInput } from "@inntris/x402-adapter";

import { actionFromMockCardAuthorisation, actionFromPaidMcpToolCall } from "./bindings.js";
import type { MultiRailConformanceCase } from "./suite.js";

const hash = (character: string): `sha256:${string}` => `sha256:${character.repeat(64)}`;
const principalId = "org_conformance";
const agentId = "agent_conformance_01";
const purpose = "research_api";
const payee = "0x0000000000000000000000000000000000000001";

const x402Input: X402BindingInput = {
  paymentRequirements: {
    scheme: "exact",
    network: "eip155:8453",
    asset: "USDC",
    amount: "4500000",
    payTo: payee,
    maxTimeoutSeconds: 60,
    extra: {},
  },
  resource: "https://example.test/research",
  principalId,
  agentId,
  purpose,
  assetDecimals: 6,
};

const ap2Input: AP2RuntimeGateInput = {
  mandates: {
    version: "inntris-ap2-mandate-presentation-v1",
    checkout_mandate_token: "checkout.open~~checkout.closed",
    payment_mandate_token: "payment.open~~payment.closed",
    checkout_jwt: "merchant.checkout.jwt",
    checkout_audience: "merchant-research-api",
    checkout_nonce: "checkout-nonce",
    checkout_issuer: "merchant-research-api",
    payment_audience: "payment-processor",
    payment_nonce: "payment-nonce",
  },
  principalId,
  agentId,
  resource: "https://example.test/research",
  purpose,
  expectedMerchantId: "merchant-research-api",
  expectedAmountMinor: "450",
  expectedCurrency: "USD",
};

function ap2Verification(amountMinor = "450", mandateHash = hash("4")): AP2OfficialVerification {
  return {
    version: "inntris-ap2-official-verification-v1",
    sdk: {
      repository: AP2_OFFICIAL_REPOSITORY,
      commit: AP2_OFFICIAL_SDK_COMMIT,
      protocol_version: AP2_PROTOCOL_VERSION,
    },
    mode: "autonomous",
    intent: {
      verified: true,
      checkout_open_mandate_hash: hash("1"),
      payment_open_mandate_hash: hash("2"),
    },
    checkout: {
      verified: true,
      mandate_hash: hash("3"),
      expires_at: "2026-07-29T12:05:00.000Z",
      checkout_hash: "checkoutHashConformance",
      checkout_id: "checkout-conformance",
      merchant_id: "merchant-research-api",
      merchant_name: "Research API",
    },
    payment: {
      verified: true,
      mandate_hash: mandateHash,
      expires_at: "2026-07-29T12:05:00.000Z",
      transaction_id: "checkoutHashConformance",
      payee_id: "merchant-research-api",
      payee_name: "Research API",
      amount_minor: amountMinor,
      currency: "USD",
      payment_instrument_type: "card",
    },
    verified_at: "2026-07-29T12:00:00.000Z",
  };
}

const evmInput: EvmWalletGateInput = {
  transaction: {
    type: "eip1559",
    chain_id: "8453",
    from: "0x0000000000000000000000000000000000000002",
    to: payee,
    value_wei: "4500000000000000000",
    data: "0x",
    nonce: "7",
    gas_limit: "21000",
    max_fee_per_gas_wei: "2000000000",
    max_priority_fee_per_gas_wei: "1000000000",
    gas_price_wei: null,
    access_list: [],
  },
  principalId,
  agentId,
  resource: "https://example.test/research",
  purpose,
  asset: "ETH",
  assetDecimals: 18,
};

const cardInput = {
  version: "inntris-mock-card-authorisation-v1",
  authorisationRequestId: "card-request-001",
  principalId,
  agentId,
  resource: "https://card.example.test/authorise",
  purpose,
  amount: "4.50",
  asset: "USD",
  merchantId: "merchant-card-demo",
  cardNetwork: "visa",
  credentialReference: "tokenised-card-reference",
} as const;

const mcpInput = {
  version: "inntris-paid-mcp-tool-call-v1",
  toolCallId: "tool-call-001",
  principalId,
  agentId,
  resource: "https://mcp.example.test/tools/research",
  purpose,
  amount: "4.50",
  asset: "USD",
  serverId: "mcp-research-server",
  toolName: "paid_research",
  arguments: { query: "renewable energy", limit: 5 },
  paymentReference: "mcp-payment-001",
} as const;

export function createPublicConformanceCases(): MultiRailConformanceCase[] {
  return [
    {
      rail: "x402",
      action: actionFromX402(x402Input),
      mutatedAction: actionFromX402({
        ...x402Input,
        paymentRequirements: { ...x402Input.paymentRequirements, amount: "4600000" },
      }),
    },
    {
      rail: "ap2",
      action: actionFromAP2(ap2Input, ap2Verification(), 2),
      mutatedAction: actionFromAP2(ap2Input, ap2Verification("460", hash("5")), 2),
    },
    {
      rail: "evm",
      action: actionFromEvmTransaction(evmInput),
      mutatedAction: actionFromEvmTransaction({
        ...evmInput,
        transaction: { ...evmInput.transaction, nonce: "8" },
      }),
    },
    {
      rail: "card",
      action: actionFromMockCardAuthorisation(cardInput),
      mutatedAction: actionFromMockCardAuthorisation({ ...cardInput, amount: "4.60" }),
    },
    {
      rail: "mcp",
      action: actionFromPaidMcpToolCall(mcpInput),
      mutatedAction: actionFromPaidMcpToolCall({
        ...mcpInput,
        arguments: { ...mcpInput.arguments, limit: 6 },
      }),
    },
  ];
}
