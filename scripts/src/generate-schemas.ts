import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

import {
  A2AActionBindingSchema,
  A2AActionReceiptSchema,
  A2APaymentSubmissionSchema,
  A2ASettlementObservationSchema,
} from "@inntris/a2a-settlement-gate";
import {
  AP2ActionReceiptSchema,
  AP2MandatePresentationSchema,
  AP2OfficialVerificationSchema,
} from "@inntris/ap2-runtime-gate";
import {
  InntrisActionV1Schema,
  InntrisDecisionV1Schema,
  KeyRegistrySchema,
} from "@inntris/decision-core";
import { ExecutionOperationRecordSchema } from "@inntris/execution-reconciliation";
import { InntrisPolicyV1Schema } from "@inntris/policy-engine";
import {
  MockCardAuthorisationInputSchema,
  PaidMcpToolCallInputSchema,
} from "@inntris/multi-rail-conformance";
import {
  EvmUnsignedTransactionSchema,
  EvmWalletGateInputSchema,
} from "@inntris/wallet-signing-gate";
import { format } from "prettier";
import { toJSONSchema, type ZodType } from "zod";

const schemas: [string, string, ZodType][] = [
  [
    "inntris-a2a-action-binding-v1.schema.json",
    "Inntris A2A Action Binding v1",
    A2AActionBindingSchema,
  ],
  [
    "inntris-a2a-action-receipt-v1.schema.json",
    "Inntris A2A Action Receipt v1",
    A2AActionReceiptSchema,
  ],
  [
    "inntris-a2a-payment-submission-v1.schema.json",
    "Inntris A2A Payment Submission v1",
    A2APaymentSubmissionSchema,
  ],
  [
    "inntris-a2a-settlement-observation-v1.schema.json",
    "Inntris A2A Settlement Observation v1",
    A2ASettlementObservationSchema,
  ],
  [
    "inntris-ap2-action-receipt-v1.schema.json",
    "Inntris AP2 Action Receipt v1",
    AP2ActionReceiptSchema,
  ],
  [
    "inntris-ap2-mandate-presentation-v1.schema.json",
    "Inntris AP2 Mandate Presentation v1",
    AP2MandatePresentationSchema,
  ],
  [
    "inntris-ap2-official-verification-v1.schema.json",
    "Inntris AP2 Official Verification v1",
    AP2OfficialVerificationSchema,
  ],
  ["inntris-action-v1.schema.json", "Inntris Action v1", InntrisActionV1Schema],
  ["inntris-decision-v1.schema.json", "Inntris Decision v1", InntrisDecisionV1Schema],
  [
    "inntris-execution-operation-v1.schema.json",
    "Inntris Execution Operation v1",
    ExecutionOperationRecordSchema,
  ],
  [
    "inntris-evm-unsigned-transaction-v1.schema.json",
    "Inntris EVM Unsigned Transaction v1",
    EvmUnsignedTransactionSchema,
  ],
  [
    "inntris-evm-wallet-gate-input-v1.schema.json",
    "Inntris EVM Wallet Gate Input v1",
    EvmWalletGateInputSchema,
  ],
  [
    "inntris-mock-card-authorisation-input-v1.schema.json",
    "Inntris Mock Card Authorisation Input v1",
    MockCardAuthorisationInputSchema,
  ],
  [
    "inntris-paid-mcp-tool-call-input-v1.schema.json",
    "Inntris Paid MCP Tool Call Input v1",
    PaidMcpToolCallInputSchema,
  ],
  ["inntris-key-registry-v1.schema.json", "Inntris Key Registry v1", KeyRegistrySchema],
  ["inntris-policy-v1.schema.json", "Inntris Policy v1", InntrisPolicyV1Schema],
];

const directory = resolve("schemas");
await mkdir(directory, { recursive: true });
for (const [filename, title, schema] of schemas) {
  const jsonSchema = {
    $id: `https://schemas.inntris.com/${filename}`,
    title,
    ...toJSONSchema(schema, {
      target: "draft-2020-12",
      unrepresentable: "any",
    }),
  };
  await writeFile(
    resolve(directory, filename),
    await format(JSON.stringify(jsonSchema), { parser: "json", printWidth: 100 }),
    "utf8",
  );
}
process.stdout.write(`Generated ${schemas.length} JSON schemas\n`);
