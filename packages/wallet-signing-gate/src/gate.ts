import {
  hashCanonical,
  type Clock,
  type DecisionProvider,
  type InntrisDecisionV1,
  type KeyRegistry,
} from "@inntris/decision-core";
import { verifyDecision } from "@inntris/decision-verifier";
import { keccak256, type Hex } from "viem";

import { actionFromEvmTransaction, normaliseEvmTransaction } from "./binding.js";
import { InMemoryEvmExecutionStore, type EvmExecutionStore } from "./store.js";
import {
  EvmBroadcastResultSchema,
  EvmWalletGateInputSchema,
  SignedEvmTransactionSchema,
  type EvmBroadcaster,
  type EvmWalletAuthorisation,
  type EvmWalletExecutionResult,
  type EvmWalletGateInput,
  type EvmWalletGateReasonCode,
  type InjectedEvmWallet,
} from "./types.js";
import { verifySignedEvmTransaction } from "./verification.js";

export interface InntrisEvmWalletGateOptions {
  provider: DecisionProvider;
  keyRegistry: KeyRegistry;
  wallet: InjectedEvmWallet;
  broadcaster: EvmBroadcaster;
  executionStore?: EvmExecutionStore;
  expectedPolicyVersion?: string;
  clock?: Clock;
}

export class InntrisEvmWalletGateError extends Error {
  override readonly name = "InntrisEvmWalletGateError";

  constructor(
    message: string,
    readonly reasonCode: EvmWalletGateReasonCode,
    readonly causeCode?: string,
  ) {
    super(message);
  }
}

function reject(message: string, reasonCode: EvmWalletGateReasonCode, causeCode?: string): never {
  throw new InntrisEvmWalletGateError(message, reasonCode, causeCode);
}

export class InntrisEvmWalletGate {
  readonly #clock: Clock;
  readonly #executionStore: EvmExecutionStore;

  constructor(readonly options: InntrisEvmWalletGateOptions) {
    this.#clock = options.clock ?? { now: () => new Date() };
    this.#executionStore = options.executionStore ?? new InMemoryEvmExecutionStore();
  }

  async #prepare(inputValue: EvmWalletGateInput) {
    const parsed = EvmWalletGateInputSchema.safeParse(inputValue);
    if (!parsed.success) {
      return reject("The EVM wallet request is invalid", "INVALID_EVM_INPUT");
    }
    const input = parsed.data;
    const transaction = normaliseEvmTransaction(input.transaction);
    let walletAddress: string;
    try {
      walletAddress = (await this.options.wallet.getAddress()).toLowerCase();
    } catch (error) {
      return reject(
        "The injected wallet is unavailable",
        "WALLET_UNAVAILABLE",
        error instanceof Error ? error.name : undefined,
      );
    }
    if (walletAddress !== transaction.from) {
      return reject(
        "The unsigned transaction belongs to a different wallet",
        "WALLET_ADDRESS_MISMATCH",
      );
    }
    return {
      input,
      transaction,
      action: actionFromEvmTransaction({ ...input, transaction }),
    };
  }

  async authorise(input: EvmWalletGateInput): Promise<EvmWalletAuthorisation> {
    const prepared = await this.#prepare(input);
    let decision: InntrisDecisionV1;
    try {
      decision = await this.options.provider.evaluate(prepared.action);
    } catch (error) {
      return reject(
        "Inntris policy evaluation failed closed",
        "DECISION_INVALID",
        error instanceof Error ? error.name : undefined,
      );
    }
    const verification = verifyDecision({
      decision,
      action: prepared.action,
      keyRegistry: this.options.keyRegistry,
      at: this.#clock.now(),
      expectedPolicyVersion: this.options.expectedPolicyVersion,
    });
    if (!verification.valid) {
      return reject(
        "The Inntris decision did not verify against the exact unsigned transaction",
        "DECISION_INVALID",
        verification.reason_codes.join(","),
      );
    }
    if (decision.verdict !== "ALLOW") {
      return reject(
        "Current organisational policy did not allow wallet signing",
        "DECISION_NOT_ALLOW",
      );
    }
    return { action: prepared.action, decision };
  }

  async signAndBroadcast(
    input: EvmWalletGateInput,
    decision: InntrisDecisionV1,
  ): Promise<EvmWalletExecutionResult> {
    const prepared = await this.#prepare(input);
    const verification = verifyDecision({
      decision,
      action: prepared.action,
      keyRegistry: this.options.keyRegistry,
      at: this.#clock.now(),
      expectedPolicyVersion: this.options.expectedPolicyVersion,
    });
    if (!verification.valid) {
      return reject(
        "The Inntris decision is not valid for the transaction presented at signing time",
        "DECISION_INVALID",
        verification.reason_codes.join(","),
      );
    }
    if (decision.verdict !== "ALLOW") {
      return reject("Only an ALLOW decision can reach wallet signing", "DECISION_NOT_ALLOW");
    }

    const protocolReference = prepared.action.protocol_reference;
    if (protocolReference.type !== "evm") {
      return reject("The decision is not bound to an EVM transaction", "DECISION_INVALID");
    }
    const executionRef = `evm-execution:${hashCanonical({
      version: "inntris-evm-execution-ref-v1",
      decision_id: decision.decision_id,
      action_hash: decision.action_hash,
      unsigned_transaction_hash: protocolReference.unsigned_transaction_hash,
    }).slice(7)}`;
    let consumption;
    try {
      consumption = await this.options.provider.consume({
        decision_id: decision.decision_id,
        action_hash: decision.action_hash,
        execution_ref: executionRef,
      });
    } catch (error) {
      return reject(
        "Decision consumption is unavailable; wallet signing is blocked",
        "DECISION_CONSUMPTION_FAILED",
        error instanceof Error ? error.name : undefined,
      );
    }
    if (!consumption.success) {
      return reject(
        "Decision consumption failed; wallet signing is blocked",
        "DECISION_CONSUMPTION_FAILED",
        consumption.reason_code,
      );
    }

    const bindingHash = hashCanonical({
      version: "inntris-evm-execution-binding-v1",
      action_hash: decision.action_hash,
      unsigned_transaction_hash: protocolReference.unsigned_transaction_hash,
      wallet_address: prepared.transaction.from,
    });
    let claim;
    try {
      claim = await this.#executionStore.claim({
        unsignedTransactionHash: protocolReference.unsigned_transaction_hash,
        bindingHash,
        executionRef,
      });
    } catch (error) {
      return reject(
        "EVM execution state is unavailable; wallet signing is blocked",
        "EVM_EXECUTION_STORE_UNAVAILABLE",
        error instanceof Error ? error.name : undefined,
      );
    }
    if (claim.status === "conflict") {
      return reject(
        "The unsigned transaction is already bound to a different decision",
        "EVM_EXECUTION_CONFLICT",
      );
    }
    if (claim.status === "in_progress") {
      return reject(
        "The unsigned transaction has an unresolved signing or broadcast attempt",
        "EVM_EXECUTION_IN_PROGRESS",
      );
    }
    if (claim.status === "completed") {
      return {
        action: claim.action,
        decision: claim.decision,
        unsigned_transaction_hash: protocolReference.unsigned_transaction_hash,
        signed_transaction: claim.signedTransaction,
        transaction_hash: claim.transactionHash,
        execution_ref: claim.executionRef,
        replayed: true,
      };
    }

    let rawSignedTransaction: unknown;
    try {
      rawSignedTransaction = await this.options.wallet.signTransaction(prepared.transaction);
    } catch (error) {
      return reject(
        "The injected wallet failed to sign the authorised transaction",
        "WALLET_SIGNING_FAILED",
        error instanceof Error ? error.name : undefined,
      );
    }
    const signedResult = SignedEvmTransactionSchema.safeParse(rawSignedTransaction);
    if (!signedResult.success) {
      return reject(
        "The wallet returned an invalid signed transaction",
        "INVALID_SIGNED_TRANSACTION",
      );
    }
    if (!(await verifySignedEvmTransaction(signedResult.data, prepared.transaction))) {
      return reject(
        "The wallet signed a different transaction or with a different account",
        "INVALID_SIGNED_TRANSACTION",
      );
    }

    let rawBroadcast: unknown;
    try {
      rawBroadcast = await this.options.broadcaster.broadcastTransaction({
        signedTransaction: signedResult.data,
        unsignedTransaction: prepared.transaction,
        executionRef,
      });
    } catch (error) {
      return reject(
        "Broadcast failed after wallet signing; reconciliation is required",
        "BROADCAST_FAILED",
        error instanceof Error ? error.name : undefined,
      );
    }
    const broadcast = EvmBroadcastResultSchema.safeParse(rawBroadcast);
    const expectedTransactionHash = keccak256(signedResult.data as Hex);
    if (
      !broadcast.success ||
      broadcast.data.transaction_hash.toLowerCase() !== expectedTransactionHash
    ) {
      return reject(
        "The broadcaster returned a transaction hash that does not match the signed bytes",
        "INVALID_BROADCAST_RESULT",
      );
    }
    try {
      await this.#executionStore.complete({
        unsignedTransactionHash: protocolReference.unsigned_transaction_hash,
        bindingHash,
        executionRef,
        action: prepared.action,
        decision,
        unsignedTransaction: prepared.transaction,
        signedTransaction: signedResult.data,
        transactionHash: expectedTransactionHash,
      });
    } catch (error) {
      return reject(
        "The transaction was broadcast but execution state could not be finalised",
        "EVM_EXECUTION_STORE_UNAVAILABLE",
        error instanceof Error ? error.name : undefined,
      );
    }
    return {
      action: prepared.action,
      decision,
      unsigned_transaction_hash: protocolReference.unsigned_transaction_hash,
      signed_transaction: signedResult.data,
      transaction_hash: expectedTransactionHash,
      execution_ref: executionRef,
      replayed: false,
    };
  }

  async execute(input: EvmWalletGateInput): Promise<EvmWalletExecutionResult> {
    const authorisation = await this.authorise(input);
    return this.signAndBroadcast(input, authorisation.decision);
  }
}
