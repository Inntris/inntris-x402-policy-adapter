import {
  createPublicDemoSigner,
  type ConsumeDecisionResult,
  type DecisionProvider,
} from "@inntris/decision-core";
import { InntrisPolicyV1Schema, LocalPolicyDecisionProvider } from "@inntris/policy-engine";
import {
  InMemoryEvmExecutionStore,
  InntrisEvmWalletGate,
  evmUnsignedTransactionHash,
  type EvmExecutionStore,
  type EvmWalletGateInput,
  type InjectedEvmWallet,
} from "@inntris/wallet-signing-gate";
import { keccak256, type Address, type Hex } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { describe, expect, it, vi } from "vitest";

import { testContext } from "../helpers.js";

const walletAccount = privateKeyToAccount(generatePrivateKey());
const from = walletAccount.address.toLowerCase();
const to = "0x0000000000000000000000000000000000000001";

const input: EvmWalletGateInput = {
  transaction: {
    type: "eip1559",
    chain_id: "8453",
    from,
    to,
    value_wei: "4500000000000000000",
    data: "0x",
    nonce: "7",
    gas_limit: "21000",
    max_fee_per_gas_wei: "2000000000",
    max_priority_fee_per_gas_wei: "1000000000",
    gas_price_wei: null,
    access_list: [],
  },
  principalId: "org_demo",
  agentId: "agent_research_01",
  resource: "https://example.test/research",
  purpose: "research_api",
  asset: "ETH",
  assetDecimals: 18,
};

async function signTransaction(transaction: EvmWalletGateInput["transaction"]): Promise<Hex> {
  const common = {
    chainId: Number(transaction.chain_id),
    to: transaction.to as Address,
    value: BigInt(transaction.value_wei),
    data: transaction.data as Hex,
    nonce: Number(transaction.nonce),
    gas: BigInt(transaction.gas_limit),
  };
  if (transaction.type === "legacy") {
    return walletAccount.signTransaction({
      ...common,
      type: "legacy",
      gasPrice: BigInt(transaction.gas_price_wei!),
    });
  }
  return walletAccount.signTransaction({
    ...common,
    type: "eip1559",
    maxFeePerGas: BigInt(transaction.max_fee_per_gas_wei!),
    maxPriorityFeePerGas: BigInt(transaction.max_priority_fee_per_gas_wei!),
    accessList: transaction.access_list.map((entry) => ({
      address: entry.address as Address,
      storageKeys: entry.storage_keys as readonly Hex[],
    })),
  });
}

async function walletContext(
  options: {
    provider?: DecisionProvider;
    wallet?: InjectedEvmWallet;
    executionStore?: EvmExecutionStore;
    events?: string[];
  } = {},
) {
  const base = await testContext();
  const policy = InntrisPolicyV1Schema.parse({
    ...base.provider.options.policy,
    rails: {
      ...base.provider.options.policy.rails,
      evm: {
        allowed_networks: ["eip155:8453"],
        allowed_assets: ["ETH"],
      },
    },
  });
  const localProvider = new LocalPolicyDecisionProvider({
    policy,
    signer: createPublicDemoSigner(),
    clock: base.clock,
  });
  const events = options.events ?? [];
  const provider =
    options.provider ??
    ({
      evaluate: localProvider.evaluate.bind(localProvider),
      consume: async (consumeInput) => {
        events.push("consume");
        return localProvider.consume(consumeInput);
      },
    } satisfies DecisionProvider);
  const wallet =
    options.wallet ??
    ({
      getAddress: vi.fn(async () => from),
      signTransaction: vi.fn(async (transaction: EvmWalletGateInput["transaction"]) => {
        events.push("sign");
        return signTransaction(transaction);
      }),
    } satisfies InjectedEvmWallet);
  const broadcastTransaction = vi.fn(
    async ({ signedTransaction }: { signedTransaction: string }) => {
      events.push("broadcast");
      return { transaction_hash: keccak256(signedTransaction as Hex) };
    },
  );
  const gate = new InntrisEvmWalletGate({
    provider,
    keyRegistry: base.keyRegistry,
    wallet,
    broadcaster: { broadcastTransaction },
    executionStore: options.executionStore ?? new InMemoryEvmExecutionStore(),
    expectedPolicyVersion: "1",
    clock: base.clock,
  });
  return { ...base, localProvider, provider, wallet, broadcastTransaction, gate, events };
}

function gateReason(reasonCode: string): { name: string; reasonCode: string } {
  return { name: "InntrisEvmWalletGateError", reasonCode };
}

describe("EVM wallet signing gate", () => {
  it("consumes a verified ALLOW before signing and broadcasting", async () => {
    const context = await walletContext();

    const result = await context.gate.execute(input);

    expect(result).toMatchObject({
      replayed: false,
    });
    expect(result.transaction_hash).toBe(keccak256(result.signed_transaction as Hex));
    expect(result.decision.verdict).toBe("ALLOW");
    expect(result.action.rail).toBe("evm");
    expect(context.events).toEqual(["consume", "sign", "broadcast"]);
  });

  it("supports an exact legacy transaction", async () => {
    const context = await walletContext();
    const legacy: EvmWalletGateInput = {
      ...input,
      transaction: {
        ...input.transaction,
        type: "legacy",
        max_fee_per_gas_wei: null,
        max_priority_fee_per_gas_wei: null,
        gas_price_wei: "2000000000",
        access_list: [],
      },
    };

    const result = await context.gate.execute(legacy);

    expect(result.decision.verdict).toBe("ALLOW");
    expect(result.action.protocol_reference.type).toBe("evm");
    expect(context.events).toEqual(["consume", "sign", "broadcast"]);
  });

  it("never reaches signing when policy blocks the value", async () => {
    const context = await walletContext();
    const blocked = {
      ...input,
      transaction: { ...input.transaction, value_wei: "101000000000000000000" },
    };

    await expect(context.gate.execute(blocked)).rejects.toMatchObject(
      gateReason("DECISION_NOT_ALLOW"),
    );
    expect(context.events).not.toContain("sign");
    expect(context.broadcastTransaction).not.toHaveBeenCalled();
  });

  it("detects transaction changes between authorisation and signing", async () => {
    const context = await walletContext();
    const authorisation = await context.gate.authorise(input);
    const changed = {
      ...input,
      transaction: { ...input.transaction, nonce: "8" },
    };

    await expect(
      context.gate.signAndBroadcast(changed, authorisation.decision),
    ).rejects.toMatchObject(gateReason("DECISION_INVALID"));
    expect(context.events).not.toContain("sign");
  });

  it("rejects a tampered decision before consumption or signing", async () => {
    const context = await walletContext();
    const authorisation = await context.gate.authorise(input);
    const tampered = {
      ...authorisation.decision,
      reason_codes: ["WITHIN_DAILY_LIMIT" as const],
    };

    await expect(context.gate.signAndBroadcast(input, tampered)).rejects.toMatchObject(
      gateReason("DECISION_INVALID"),
    );
    expect(context.events).toEqual([]);
  });

  it("blocks signing when decision consumption fails", async () => {
    const base = await walletContext();
    const consumeFailure: ConsumeDecisionResult = {
      success: false,
      status: "conflict",
      decision_id: "decision",
      execution_ref: "execution",
      reason_code: "NONCE_ALREADY_CONSUMED",
    };
    const provider: DecisionProvider = {
      evaluate: base.localProvider.evaluate.bind(base.localProvider),
      consume: async () => consumeFailure,
    };
    const context = await walletContext({ provider });

    await expect(context.gate.execute(input)).rejects.toMatchObject(
      gateReason("DECISION_CONSUMPTION_FAILED"),
    );
    expect(context.events).not.toContain("sign");
  });

  it("rejects a transaction whose sender is not the injected wallet", async () => {
    const sign = vi.fn(async (transaction: EvmWalletGateInput["transaction"]) =>
      signTransaction(transaction),
    );
    const wallet: InjectedEvmWallet = {
      getAddress: async () => "0x0000000000000000000000000000000000000003",
      signTransaction: sign,
    };
    const context = await walletContext({ wallet });

    await expect(context.gate.execute(input)).rejects.toMatchObject(
      gateReason("WALLET_ADDRESS_MISMATCH"),
    );
    expect(sign).not.toHaveBeenCalled();
  });

  it("replays a completed execution without signing or broadcasting twice", async () => {
    const context = await walletContext();
    const authorisation = await context.gate.authorise(input);

    const first = await context.gate.signAndBroadcast(input, authorisation.decision);
    const replay = await context.gate.signAndBroadcast(input, authorisation.decision);

    expect(first.replayed).toBe(false);
    expect(replay.replayed).toBe(true);
    expect(context.events.filter((event) => event === "sign")).toHaveLength(1);
    expect(context.broadcastTransaction).toHaveBeenCalledTimes(1);
  });

  it("allows only one concurrent decision to sign the same transaction", async () => {
    const context = await walletContext();
    const [first, second] = await Promise.all([
      context.gate.authorise(input),
      context.gate.authorise(input),
    ]);

    const results = await Promise.allSettled([
      context.gate.signAndBroadcast(input, first.decision),
      context.gate.signAndBroadcast(input, second.decision),
    ]);

    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    const rejected = results.find((result) => result.status === "rejected");
    expect(rejected).toBeDefined();
    if (rejected?.status === "rejected") {
      const reason: unknown = rejected.reason;
      expect(reason).toMatchObject(gateReason("EVM_EXECUTION_CONFLICT"));
    }
    expect(context.events.filter((event) => event === "sign")).toHaveLength(1);
    expect(context.broadcastTransaction).toHaveBeenCalledTimes(1);
  });

  it("leaves an uncertain broadcast in progress and blocks automatic retry", async () => {
    const context = await walletContext();
    context.broadcastTransaction.mockRejectedValueOnce(new Error("network timeout"));
    const authorisation = await context.gate.authorise(input);

    await expect(
      context.gate.signAndBroadcast(input, authorisation.decision),
    ).rejects.toMatchObject(gateReason("BROADCAST_FAILED"));
    await expect(
      context.gate.signAndBroadcast(input, authorisation.decision),
    ).rejects.toMatchObject(gateReason("EVM_EXECUTION_IN_PROGRESS"));
    expect(context.events.filter((event) => event === "sign")).toHaveLength(1);
    expect(context.broadcastTransaction).toHaveBeenCalledTimes(1);
  });

  it("rejects signed bytes for a different transaction before broadcast", async () => {
    const maliciousWallet: InjectedEvmWallet = {
      getAddress: async () => from,
      signTransaction: vi.fn(async (transaction: EvmWalletGateInput["transaction"]) =>
        signTransaction({ ...transaction, value_wei: "1" }),
      ),
    };
    const context = await walletContext({ wallet: maliciousWallet });

    await expect(context.gate.execute(input)).rejects.toMatchObject(
      gateReason("INVALID_SIGNED_TRANSACTION"),
    );
    expect(context.broadcastTransaction).not.toHaveBeenCalled();
  });

  it("rejects a broadcaster response for different signed bytes", async () => {
    const context = await walletContext();
    context.broadcastTransaction.mockResolvedValueOnce({
      transaction_hash: `0x${"ef".repeat(32)}`,
    });

    await expect(context.gate.execute(input)).rejects.toMatchObject(
      gateReason("INVALID_BROADCAST_RESULT"),
    );
    expect(context.events.filter((event) => event === "sign")).toHaveLength(1);
  });

  it("binds every signing field into the unsigned transaction hash", () => {
    const original = evmUnsignedTransactionHash(input.transaction);
    const variants = [
      { ...input.transaction, chain_id: "1" },
      { ...input.transaction, from: "0x0000000000000000000000000000000000000003" },
      { ...input.transaction, to: "0x0000000000000000000000000000000000000004" },
      { ...input.transaction, value_wei: "1" },
      { ...input.transaction, data: "0x01" },
      { ...input.transaction, nonce: "8" },
      { ...input.transaction, gas_limit: "22000" },
      { ...input.transaction, max_fee_per_gas_wei: "3000000000" },
      { ...input.transaction, max_priority_fee_per_gas_wei: "1500000000" },
      {
        ...input.transaction,
        access_list: [{ address: to, storage_keys: [`0x${"01".repeat(32)}`] }],
      },
    ];

    for (const variant of variants) {
      expect(evmUnsignedTransactionHash(variant)).not.toBe(original);
    }
  });
});
