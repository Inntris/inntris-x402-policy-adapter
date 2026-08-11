# v0.3.0 release evidence

## Scope

Release `v0.3.0` advances the reference adapter from in-memory policy demonstrations towards
deployable control boundaries:

1. PostgreSQL backed immutable decisions, approval claims, atomic consumption and cumulative spend.
2. Durable composition with the existing MTP authority and stable execution references.
3. Provider-neutral managed Ed25519 signing with local verification and controlled key rotation.
4. Official x402 test facilitator compatibility checks through the pinned SDK.
5. Durable direct x402 operation claims, explicit unknown outcomes and authoritative reconciliation.

## Hosted operating evidence

The no-secret x402 workflow ran on merged `main` commit `7d8036b3ff83b5d5966fcedc6bb8fddebd0f3b47`:

<https://github.com/Inntris/inntris-x402-policy-adapter/actions/runs/31468980259>

It completed successfully and reported:

1. x402 version 2.
2. `exact` support on Base Sepolia, `eip155:84532`.
3. Rejection of the deliberately invalid EIP 3009 signature with `invalid_exact_evm_signature`.

The exact result is committed in
[`evidence/x402-sandbox-v0.3.0.json`](../evidence/x402-sandbox-v0.3.0.json).

## Validation baseline

The reconciliation pull request passed the protected quality suite, PostgreSQL integration tests,
official AP2 SDK self test, five-rail conformance, schema and evidence reproduction, production
dependency audit, secret scanning and CodeQL before merge.

Release preparation must repeat those checks on the versioned commit before the tag and GitHub
release are created.

## Claims boundary

This evidence proves current public facilitator connectivity, advertised testnet compatibility and
fail-closed rejection. The probe never calls settlement, never loads a buyer key and moves no asset.
It does not prove a funded testnet payment, mainnet settlement, production availability, managed key
custody, disaster recovery or monitored production operation.

Direct x402 is wired to the generic durable reconciliation journal. MTP retains its own durable
bridge. A2A, AP2 and EVM still require durable production adapters at their external side-effect
boundaries. Mock card and paid MCP remain conformance bindings only.
