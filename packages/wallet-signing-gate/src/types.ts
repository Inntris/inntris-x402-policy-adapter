import {
  HashSchema,
  IdentifierSchema,
  type InntrisActionV1,
  type InntrisDecisionV1,
} from "@inntris/decision-core";
import { z } from "zod";

const UnsignedIntegerSchema = z.string().regex(/^(0|[1-9]\d*)$/u);
const PositiveIntegerSchema = z.string().regex(/^[1-9]\d*$/u);
const SafeUnsignedIntegerSchema = UnsignedIntegerSchema.refine(
  (value) => BigInt(value) <= BigInt(Number.MAX_SAFE_INTEGER),
  "Value exceeds the JavaScript safe integer range required by EVM signing libraries",
);
const SafePositiveIntegerSchema = PositiveIntegerSchema.refine(
  (value) => BigInt(value) <= BigInt(Number.MAX_SAFE_INTEGER),
  "Value exceeds the JavaScript safe integer range required by EVM signing libraries",
);
export const EvmAddressSchema = z.string().regex(/^0x[0-9a-fA-F]{40}$/u);
const HexDataSchema = z.string().regex(/^0x(?:[0-9a-fA-F]{2})*$/u);
const StorageKeySchema = z.string().regex(/^0x[0-9a-fA-F]{64}$/u);
export const SignedEvmTransactionSchema = z.string().regex(/^0x(?:[0-9a-fA-F]{2})+$/u);
export const EvmTransactionHashSchema = z.string().regex(/^0x[0-9a-fA-F]{64}$/u);

export const EvmAccessListEntrySchema = z
  .object({
    address: EvmAddressSchema,
    storage_keys: z.array(StorageKeySchema),
  })
  .strict();

export const EvmUnsignedTransactionSchema = z
  .object({
    type: z.enum(["eip1559", "legacy"]),
    chain_id: SafePositiveIntegerSchema,
    from: EvmAddressSchema,
    to: EvmAddressSchema,
    value_wei: UnsignedIntegerSchema,
    data: HexDataSchema,
    nonce: SafeUnsignedIntegerSchema,
    gas_limit: PositiveIntegerSchema,
    max_fee_per_gas_wei: UnsignedIntegerSchema.nullable(),
    max_priority_fee_per_gas_wei: UnsignedIntegerSchema.nullable(),
    gas_price_wei: UnsignedIntegerSchema.nullable(),
    access_list: z.array(EvmAccessListEntrySchema),
  })
  .strict()
  .superRefine((transaction, context) => {
    if (
      transaction.type === "eip1559" &&
      (transaction.max_fee_per_gas_wei === null ||
        transaction.max_priority_fee_per_gas_wei === null ||
        transaction.gas_price_wei !== null)
    ) {
      context.addIssue({
        code: "custom",
        message: "EIP-1559 transactions require max fee fields and prohibit gas_price_wei",
      });
    }
    if (
      transaction.type === "legacy" &&
      (transaction.gas_price_wei === null ||
        transaction.max_fee_per_gas_wei !== null ||
        transaction.max_priority_fee_per_gas_wei !== null ||
        transaction.access_list.length !== 0)
    ) {
      context.addIssue({
        code: "custom",
        message: "Legacy transactions require gas_price_wei and prohibit EIP-1559 fields",
      });
    }
  });

export const EvmWalletGateInputSchema = z
  .object({
    transaction: EvmUnsignedTransactionSchema,
    principalId: IdentifierSchema,
    agentId: IdentifierSchema,
    resource: z.url(),
    purpose: z.string().min(1).max(128),
    asset: z.string().min(1).max(128),
    assetDecimals: z.number().int().min(0).max(18),
    extensions: z.record(z.string(), z.unknown()).optional(),
  })
  .strict();

export interface EvmWalletGateInput {
  transaction: EvmUnsignedTransaction;
  principalId: string;
  agentId: string;
  resource: string;
  purpose: string;
  asset: string;
  assetDecimals: number;
  extensions?: Record<string, unknown> | undefined;
}

export type EvmUnsignedTransaction = z.infer<typeof EvmUnsignedTransactionSchema>;

export interface InjectedEvmWallet {
  getAddress(): Promise<string>;
  signTransaction(transaction: EvmUnsignedTransaction): Promise<string>;
}

export interface EvmBroadcaster {
  broadcastTransaction(input: {
    signedTransaction: string;
    unsignedTransaction: EvmUnsignedTransaction;
    executionRef: string;
  }): Promise<unknown>;
}

export const EvmBroadcastResultSchema = z
  .object({
    transaction_hash: EvmTransactionHashSchema,
  })
  .strict();

export type EvmBroadcastResult = z.infer<typeof EvmBroadcastResultSchema>;

export interface EvmWalletAuthorisation {
  action: InntrisActionV1;
  decision: InntrisDecisionV1;
}

export interface EvmWalletExecutionResult extends EvmWalletAuthorisation {
  unsigned_transaction_hash: z.infer<typeof HashSchema>;
  signed_transaction: string;
  transaction_hash: string;
  execution_ref: string;
  replayed: boolean;
}

export type EvmWalletGateReasonCode =
  | "INVALID_EVM_INPUT"
  | "WALLET_UNAVAILABLE"
  | "WALLET_ADDRESS_MISMATCH"
  | "DECISION_INVALID"
  | "DECISION_NOT_ALLOW"
  | "DECISION_CONSUMPTION_FAILED"
  | "EVM_EXECUTION_CONFLICT"
  | "EVM_EXECUTION_IN_PROGRESS"
  | "EVM_EXECUTION_STORE_UNAVAILABLE"
  | "WALLET_SIGNING_FAILED"
  | "INVALID_SIGNED_TRANSACTION"
  | "BROADCAST_FAILED"
  | "INVALID_BROADCAST_RESULT";
