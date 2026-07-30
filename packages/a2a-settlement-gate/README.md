# `@inntris/a2a-settlement-gate`

Fail closed orchestration for paid A2A tasks.

The package imports the official A2A 1.0 `Task` type from `@a2a-js/sdk`. A2A itself does not define
payment submission or settlement finality states, so those states remain explicit adapter interfaces
owned by this package.

## Enforced order

```text
PAYMENT_SUBMITTED
bind x402 payment to A2A task, context and resource
obtain and verify Inntris ALLOW decision
settle or confirm the configured finality
reverify and consume the decision
claim one delegate execution
execute the delegate
sign the action receipt
```

`PAYMENT_SUBMITTED`, `UNKNOWN`, malformed, mismatched, failed or insufficiently final settlement
evidence never reaches the delegate.

## Retry safety

The settlement provider must honour the supplied idempotency key. The execution store permits one
delegate claim for each exact task, payment, settlement and action binding. A completed retry
returns the stored receipt and result. An unresolved prior execution pauses automatically rather
than risking a second delegate call.

`InMemoryA2AExecutionStore` is a reference implementation only. Production deployments need a
durable atomic store and a reconciliation procedure for failures after settlement or delegate
claiming.

## Signed receipts

The receipt binds the task, context, resource, payment submission, Inntris decision, action hash,
settlement evidence, execution reference and delegate result hash. It is signed with the injected
Ed25519 signing provider and can be verified against an explicit Inntris key registry.
