# `@inntris/multi-rail-conformance`

Runs one shared organisational policy and one `inntris-decision-v1` contract across:

1. x402
2. AP2
3. An EVM wallet transaction
4. A mock corporate card authorisation
5. A paid MCP tool call

```bash
pnpm conformance
```

Each rail must produce a signed `ALLOW` that passes the same offline `verifyDecision` function. The
suite then changes one exact action field and requires verification of the original decision to fail
with `ACTION_HASH_MISMATCH`.

The AP2 case starts from the verified evidence structure produced by the separately tested official
SDK bridge. The card and MCP cases are deliberately mock conformance fixtures. They prove envelope
and policy portability, not live card-network or MCP billing integration.

KYA is authority above these rails, so it is deliberately absent from `REQUIRED_CONFORMANCE_RAILS`.
Run `pnpm conformance:kya` for the separate paid MCP authority scenario covering valid authority,
request and payment mutation, delegated MaxAmount and an independent Inntris policy denial.

Rail-specific data stays inside the discriminated `protocol_reference` field and the optional
versioned action extensions. The decision's top-level schema, policy binding, signature algorithm,
reason codes, expiry and nonce contract remain identical.
