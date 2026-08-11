# Changelog

## v0.3.0

1. Added an optional PostgreSQL policy state package with durable immutable decisions and atomic
   approval claims.
2. Made decision consumption, cumulative spend recording and the final daily limit check one
   transaction for PostgreSQL backed providers.
3. Added migration tooling, reference API wiring and database concurrency and rollback tests.
4. Added `@inntris/mtp-authority` to compose signed decisions with the existing MTP execution
   authority while keeping both evidence formats distinct.
5. Added durable MTP authorization, execution claim, receipt checkpoint and completion state to the
   PostgreSQL store.
6. Added fail-closed recovery tests for lost MTP responses, substituted evidence, changed execution
   references and exact x402 settlement ordering.
7. Added `@inntris/managed-signing` with an authenticated remote Ed25519 broker contract, pinned
   local signature verification and no fallback when the service fails.
8. Added startup key-registry validation, controlled rotation guidance, retired-key continuity and
   historical distrust for revoked keys.
9. Added a no-secret official x402 test-facilitator probe for advertised Base Sepolia exact support
   and fail-closed invalid-signature verification.
10. Added a weekly sandbox compatibility workflow and explicit non-settlement evidence boundary.
11. Added `@inntris/execution-reconciliation` with exact-bound operation claims, explicit unknown
    outcomes and evidence-bearing authoritative resolution.
12. Added durable PostgreSQL execution operations and an authenticated read-only unresolved queue to
    the reference API.
13. Wired direct x402 settlement to prepare state before consumption, claim immediately before the
    external call and block retry whenever the prior outcome is unresolved.
14. Added an executable failure matrix covering concurrent claims, binding conflict, final failure,
    unknown outcome, state outage, finalisation outage and PostgreSQL recovery.

## v0.2.0

1. Added fail-closed A2A settlement and AP2 runtime gates.
2. Added immutable human approval supersession with atomic approval claiming.
3. Added cumulative spend recording on first decision consumption.
4. Added a fail-closed EVM wallet signing gate with signed-transaction and signer verification.
5. Added five-rail conformance across x402, AP2, EVM, mock card and paid MCP actions.
6. Added generated schemas, threat-model coverage and protected CI checks for the new packages.

## v0.1.0

Initial Phase 1 release with the rail-independent Decision Envelope, offline verifier, local policy
engine, fail-closed x402 adapter, public evidence fixtures and reference API.
