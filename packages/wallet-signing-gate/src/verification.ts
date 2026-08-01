import {
  parseTransaction,
  recoverTransactionAddress,
  type AccessList,
  type TransactionSerialized,
} from "viem";

import { normaliseEvmTransaction } from "./binding.js";
import type { EvmUnsignedTransaction } from "./types.js";

function normaliseAccessList(accessList: AccessList | undefined) {
  return (accessList ?? []).map((entry) => ({
    address: entry.address.toLowerCase(),
    storage_keys: entry.storageKeys.map((key) => key.toLowerCase()),
  }));
}

/**
 * Verifies that signed RLP bytes preserve every authorised transaction field
 * and recover to the expected injected wallet address.
 */
export async function verifySignedEvmTransaction(
  signedTransaction: string,
  expectedInput: EvmUnsignedTransaction,
): Promise<boolean> {
  const expected = normaliseEvmTransaction(expectedInput);
  const serialized = signedTransaction as TransactionSerialized;
  try {
    const parsed = parseTransaction(serialized);
    const recovered = (
      await recoverTransactionAddress({ serializedTransaction: serialized })
    ).toLowerCase();
    const accessList = "accessList" in parsed ? parsed.accessList : undefined;
    return (
      recovered === expected.from &&
      parsed.type === expected.type &&
      String(parsed.chainId) === expected.chain_id &&
      parsed.to?.toLowerCase() === expected.to &&
      (parsed.value ?? 0n).toString() === expected.value_wei &&
      (parsed.data ?? "0x").toLowerCase() === expected.data &&
      String(parsed.nonce) === expected.nonce &&
      (parsed.gas?.toString() ?? null) === expected.gas_limit &&
      (parsed.maxFeePerGas?.toString() ?? null) === expected.max_fee_per_gas_wei &&
      (parsed.maxPriorityFeePerGas?.toString() ?? null) === expected.max_priority_fee_per_gas_wei &&
      (parsed.gasPrice?.toString() ?? null) === expected.gas_price_wei &&
      JSON.stringify(normaliseAccessList(accessList)) === JSON.stringify(expected.access_list)
    );
  } catch {
    return false;
  }
}
