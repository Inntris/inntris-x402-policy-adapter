# `@inntris/mtp-authority`

Composes the public signed Inntris Decision Envelope with the existing MTP execution authority. Both
approvals must succeed before an x402 guard may call settlement.

The Decision Envelope remains the exact, offline-verifiable x402 policy proof. MTP adds
registered-agent policy, trust, rate and spend controls. It does not replace the envelope or weaken
its exact amount, payee, network, resource and payment-requirements binding.

Consumption is deliberately ordered:

1. Claim one stable execution reference in durable bridge state.
2. Consume the MTP token using that reference.
3. Persist the MTP consumption receipt.
4. Consume the signed Decision Envelope using the same reference.
5. Return success to the rail guard, which may then settle.

A lost MTP response is retried with the same reference and returns the original receipt. A crash
after MTP consumption resumes at the local consumption step. A different reference conflicts. Any
unavailable or malformed authority fails closed.

Use `InMemoryMtpAuthorityStateStore` only for tests. Production deployments must inject the
PostgreSQL implementation from `@inntris/postgres-store`.

The first release composes automatic `ALLOW` decisions. Human approval resolution remains on the
underlying provider until the cross-service approval state machine is made recoverable across
crashes.
