import { InntrisActionV1Schema, hashCanonical, type InntrisActionV1 } from "@inntris/decision-core";

import {
  EvmWalletGateInputSchema,
  type EvmUnsignedTransaction,
  type EvmWalletGateInput,
} from "./types.js";

export class EvmBindingError extends Error {
  override readonly name = "EvmBindingError";
}

export function normaliseEvmTransaction(input: EvmUnsignedTransaction): EvmUnsignedTransaction {
  const transaction = EvmWalletGateInputSchema.shape.transaction.parse(input);
  return {
    ...transaction,
    from: transaction.from.toLowerCase(),
    to: transaction.to.toLowerCase(),
    data: transaction.data.toLowerCase(),
    access_list: transaction.access_list.map((entry) => ({
      address: entry.address.toLowerCase(),
      storage_keys: entry.storage_keys.map((key) => key.toLowerCase()),
    })),
  };
}

export function evmUnsignedTransactionHash(transaction: EvmUnsignedTransaction): string {
  return hashCanonical(normaliseEvmTransaction(transaction));
}

export function formatEvmAmount(valueWei: string, decimals: number): string {
  if (!/^(0|[1-9]\d*)$/u.test(valueWei)) {
    throw new EvmBindingError("EVM value must be an unsigned wei integer string");
  }
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 18) {
    throw new EvmBindingError("assetDecimals must be an integer from 0 to 18");
  }
  const padded = valueWei.padStart(decimals + 1, "0");
  const whole = decimals === 0 ? padded : padded.slice(0, -decimals);
  const rawFraction = decimals === 0 ? "" : padded.slice(-decimals);
  let fraction = rawFraction;
  while (fraction.length > 2 && fraction.endsWith("0")) {
    fraction = fraction.slice(0, -1);
  }
  if (fraction.length < 2) {
    fraction = fraction.padEnd(2, "0");
  }
  return `${BigInt(whole).toString()}.${fraction}`;
}

export function actionFromEvmTransaction(inputValue: EvmWalletGateInput): InntrisActionV1 {
  const input = EvmWalletGateInputSchema.parse(inputValue);
  const transaction = normaliseEvmTransaction(input.transaction);
  return InntrisActionV1Schema.parse({
    version: "inntris-action-v1",
    principal_id: input.principalId,
    agent_id: input.agentId,
    action_type: "financial_transaction",
    rail: "evm",
    transaction: {
      amount: formatEvmAmount(transaction.value_wei, input.assetDecimals),
      asset: input.asset,
      network: `eip155:${transaction.chain_id}`,
      payee: transaction.to,
      purpose: input.purpose,
    },
    protocol_reference: {
      type: "evm",
      resource: input.resource,
      transaction_type: transaction.type,
      chain_id: transaction.chain_id,
      from: transaction.from,
      to: transaction.to,
      value_wei: transaction.value_wei,
      nonce: transaction.nonce,
      unsigned_transaction_hash: evmUnsignedTransactionHash(transaction),
      data_hash: hashCanonical(transaction.data),
    },
    extensions: {
      ...input.extensions,
      inntris_evm: {
        unsigned_transaction: transaction,
      },
    },
  });
}
