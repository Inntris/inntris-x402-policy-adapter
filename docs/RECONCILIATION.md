# Execution reconciliation

An Inntris decision proves authorisation. It does not prove whether an external side effect
completed. `@inntris/execution-reconciliation` records the state around that boundary so a timeout
or process failure cannot trigger an unsafe automatic retry.

## State model

```text
prepared -> in_progress -> succeeded
                        -> failed_final
                        -> outcome_unknown -> succeeded
                                           -> failed_final
```

`prepared` is written before decision consumption. `in_progress` is claimed immediately before the
external call. Only `prepared` may be claimed automatically. `in_progress` and `outcome_unknown`
block retries until authoritative evidence resolves them.

The operation ID is the canonical hash of the rail, operation kind and stable execution reference.
The stored binding also covers the decision ID and action hash. Reusing a reference with different
evidence is a conflict, not an idempotent retry.

## Direct x402 integration

Inject an `ExecutionReconciliationStore` into `InntrisX402Guard`:

```ts
const guard = new InntrisX402Guard({
  provider,
  keyRegistry,
  reconciliationStore,
});
```

With a store configured, the guard performs this sequence:

1. Verify the signed decision and exact current action.
2. Persist the prepared operation.
3. Consume the decision with the stable execution reference.
4. Atomically claim the operation immediately before settlement.
5. Call the settlement executor once.
6. Record success, a known final failure, or an unknown outcome.

A thrown settlement error is `outcome_unknown` by default because a timeout does not prove that the
facilitator rejected the payment. An executor may supply `classifySettlementError` only when a
specific error proves that no side effect occurred. The external executor must use the same stable
execution reference as its idempotency key.

The success outcome reference is the stable execution reference. It is not represented as an
on-chain transaction hash. An authoritative resolver may later attach the rail's own outcome
reference when resolving an unknown operation.

## Failure matrix

| Condition                                   | Stored state    | Automatic external call      | Operator action                                  |
| ------------------------------------------- | --------------- | ---------------------------- | ------------------------------------------------ |
| State store unavailable before consumption  | none            | blocked                      | restore state service and retry the same request |
| Same prepared binding is retried            | prepared        | one claimant may proceed     | none                                             |
| Reference is reused with changed binding    | unchanged       | blocked                      | investigate the conflicting caller               |
| Prior attempt is in progress                | in_progress     | blocked                      | confirm the rail outcome                         |
| Settlement returns successfully             | succeeded       | completed once               | none                                             |
| Settlement returns a proven final rejection | failed_final    | blocked permanently          | inspect the recorded error                       |
| Settlement throws or times out              | outcome_unknown | blocked                      | reconcile against authoritative rail evidence    |
| State update fails after settlement returns | in_progress     | blocked                      | reconcile against authoritative rail evidence    |
| Unknown outcome is confirmed successful     | succeeded       | blocked as already completed | retain the resolver evidence                     |
| Unknown outcome is confirmed rejected       | failed_final    | blocked permanently          | retain the resolver evidence                     |

The test suite executes every row that can be simulated locally, including concurrent claim, binding
substitution, PostgreSQL restart, state-store outage and post-settlement journal failure.

## Operator workflow

The reference API exposes a read-only queue when PostgreSQL is configured:

```text
GET /v1/operations/unresolved?updated_before=2026-08-02T12:00:00.000Z&limit=100
Authorization: Bearer <INNTRIS_SERVICE_API_KEY>
```

The endpoint never changes state. It returns only `in_progress` and `outcome_unknown` records. A
production reconciler should:

1. Query records older than the rail-specific grace period.
2. Look up the exact execution reference through an authoritative facilitator, chain or executor.
3. Confirm the stored binding before resolving anything.
4. Call `resolve` with the resolver identity, evidence reference and a concise resolution note.
5. Alert when an operation remains unresolved beyond the service objective.

Do not resolve from application logs, an agent assertion or a fresh payment attempt. Resolution must
come from authoritative external evidence.

## Coverage boundary

The durable PostgreSQL store supports operation kinds for x402 settlement, A2A settlement and
delegate execution, AP2 delegate execution, EVM broadcast and MTP consumption. Direct x402 is the
first guard wired to this generic journal.

MTP already has its own durable PostgreSQL bridge and safe same-reference retry. The current A2A,
AP2 and EVM gates retain their existing execution-store contracts, which are in memory by default.
Their production adapters must either connect those contracts to durable state or adopt this journal
at the actual side-effect boundary. Mock card and paid MCP remain conformance bindings only; they do
not claim live executor enforcement.

## Retention and access

Restrict `inntris.execution_operations` to the runtime and reconciliation roles. Treat resolver
identity and notes as audit evidence. Archive resolved rows according to the organisation's payment
record policy. A prepared record left by failed decision consumption cannot cause a side effect and
may be cleaned up only after its associated decision has expired and operational policy permits it.
