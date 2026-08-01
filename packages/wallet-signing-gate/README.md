# `@inntris/wallet-signing-gate`

Fail-closed EVM wallet signing gate for an injected wallet provider.

The package never receives or stores a private key. It canonicalises the complete unsigned
transaction, evaluates organisational policy, verifies the signed Inntris Decision Envelope against
the exact transaction, consumes the decision, atomically claims the signing attempt, calls the
injected wallet and then broadcasts the returned signed transaction.

Before broadcast, viem parses the signed RLP transaction and recovers its signer. Every parsed field
and the recovered address must match the authorised unsigned transaction. The package pins viem
`2.55.8` in the lockfile.

```text
unsigned transaction
  -> canonical Inntris action
  -> signed Inntris decision
  -> local decision verification
  -> single-use decision consumption
  -> atomic execution claim
  -> wallet.signTransaction
  -> broadcaster.broadcastTransaction
```

`BLOCK`, `REQUIRE_APPROVAL`, invalid signatures, changed transaction fields, unknown keys, expired
decisions and consumption failures never reach `wallet.signTransaction`.

## Transaction model

The first version supports strict EIP-1559 and legacy value transactions. Every signing field is a
decimal string or canonical hex string so JavaScript number precision cannot alter the transaction.
The action binds chain ID, sender, recipient, value, nonce, calldata, gas, fees and access list
through the canonical unsigned transaction hash.

## Production integration

Inject:

1. A wallet adapter implementing `getAddress` and `signTransaction`
2. A broadcaster implementing `broadcastTransaction`
3. A durable `EvmExecutionStore` shared by every executor instance

The default store is process local. If signing or broadcast becomes uncertain, the execution remains
in progress and automatic retry is blocked for reconciliation.
