# `@inntris/x402-adapter`

A fail-closed guard around `@x402/core` 2.20.0. The package imports official x402
`PaymentRequirements` and `PaymentPayload` types and validates them with the SDK schemas.

Inntris does not settle the payment. A caller injects its settlement function, and that function is
not invoked unless evaluation, local verification and single-use consumption all succeed.

Production callers should also inject an `ExecutionReconciliationStore`. The guard then prepares
durable state before consumption, claims one settlement attempt and records success, final rejection
or unknown outcome. An unresolved earlier attempt blocks automatic retry. A settlement error is
unknown by default; use `classifySettlementError` only for rail errors that prove no side effect
occurred. See [`docs/RECONCILIATION.md`](../../docs/RECONCILIATION.md).

`actionFromKyaX402` is the higher level KYA reference binding. It derives only provisional identity
from the presentation, rejects the reserved KYA extension and must always feed the result through
`KyaAuthorityGate`, which cryptographically recomputes both identities and every financial join
before organisational policy runs.
