import {
  CanonicalAmountSchema,
  IdentifierSchema,
  InntrisActionV1Schema,
  hashCanonical,
  type InntrisActionV1,
} from "@inntris/decision-core";
import { z } from "zod";

export const MockCardAuthorisationInputSchema = z
  .object({
    version: z.literal("inntris-mock-card-authorisation-v1"),
    authorisationRequestId: IdentifierSchema,
    principalId: IdentifierSchema,
    agentId: IdentifierSchema,
    resource: z.url(),
    purpose: z.string().min(1).max(128),
    amount: CanonicalAmountSchema,
    asset: z.string().min(1).max(128),
    merchantId: IdentifierSchema,
    cardNetwork: z.string().min(1).max(64),
    credentialReference: z.string().min(1).max(256),
  })
  .strict();

export const PaidMcpToolCallInputSchema = z
  .object({
    version: z.literal("inntris-paid-mcp-tool-call-v1"),
    toolCallId: IdentifierSchema,
    principalId: IdentifierSchema,
    agentId: IdentifierSchema,
    resource: z.url(),
    purpose: z.string().min(1).max(128),
    amount: CanonicalAmountSchema,
    asset: z.string().min(1).max(128),
    serverId: z.string().min(1).max(100),
    toolName: IdentifierSchema,
    arguments: z.record(z.string(), z.json()),
    paymentReference: z.string().min(1).max(256),
  })
  .strict();

export type MockCardAuthorisationInput = z.infer<typeof MockCardAuthorisationInputSchema>;
export type PaidMcpToolCallInput = z.infer<typeof PaidMcpToolCallInputSchema>;

export function actionFromMockCardAuthorisation(
  inputValue: MockCardAuthorisationInput,
): InntrisActionV1 {
  const input = MockCardAuthorisationInputSchema.parse(inputValue);
  const cardNetwork = input.cardNetwork.toLowerCase();
  return InntrisActionV1Schema.parse({
    version: "inntris-action-v1",
    principal_id: input.principalId,
    agent_id: input.agentId,
    action_type: "financial_transaction",
    rail: "card",
    transaction: {
      amount: input.amount,
      asset: input.asset,
      network: `card:${cardNetwork}`,
      payee: input.merchantId,
      purpose: input.purpose,
    },
    protocol_reference: {
      type: "card",
      resource: input.resource,
      authorisation_request_id: input.authorisationRequestId,
      merchant_id: input.merchantId,
      card_network: cardNetwork,
      credential_reference_hash: hashCanonical(input.credentialReference),
      authorisation_request_hash: hashCanonical({
        version: "inntris-mock-card-authorisation-v1",
        authorisation_request_id: input.authorisationRequestId,
        amount: input.amount,
        asset: input.asset,
        merchant_id: input.merchantId,
        card_network: cardNetwork,
        credential_reference_hash: hashCanonical(input.credentialReference),
      }),
    },
    extensions: {
      inntris_conformance: { mock_rail: true },
    },
  });
}

export function actionFromPaidMcpToolCall(inputValue: PaidMcpToolCallInput): InntrisActionV1 {
  const input = PaidMcpToolCallInputSchema.parse(inputValue);
  return InntrisActionV1Schema.parse({
    version: "inntris-action-v1",
    principal_id: input.principalId,
    agent_id: input.agentId,
    action_type: "financial_transaction",
    rail: "mcp",
    transaction: {
      amount: input.amount,
      asset: input.asset,
      network: `mcp:${input.serverId}`,
      payee: input.serverId,
      purpose: input.purpose,
    },
    protocol_reference: {
      type: "mcp",
      resource: input.resource,
      server_id: input.serverId,
      tool_name: input.toolName,
      tool_call_id: input.toolCallId,
      tool_arguments_hash: hashCanonical(input.arguments),
      payment_reference_hash: hashCanonical(input.paymentReference),
    },
    extensions: {
      inntris_conformance: { mock_rail: true },
    },
  });
}
