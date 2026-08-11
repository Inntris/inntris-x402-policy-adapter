# `@inntris/execution-reconciliation`

Fail-closed operational state for external effects that cannot be atomic with an Inntris decision
consumption.

Every operation binds one rail, operation kind, decision, action hash and stable execution
reference. The store permits one transition from `prepared` to `in_progress`. A process or network
failure after that point becomes `outcome_unknown` and automatic retries remain blocked until an
authoritative rail observation resolves the operation.

The state machine is:

```text
prepared -> in_progress -> succeeded
                        -> failed_final
                        -> outcome_unknown -> succeeded
                                           -> failed_final
```

The resolver must supply its identity, a resolution note and an authoritative outcome reference. An
operator assertion without rail evidence is not sufficient.

The in-memory implementation is for tests and demonstrations. Use the PostgreSQL implementation in
`@inntris/postgres-store` for durable deployments.
