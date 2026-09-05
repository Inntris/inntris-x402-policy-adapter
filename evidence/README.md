# Public signed evidence

`allow.json` is a signed `ALLOW` decision produced by the intentionally public fixture identity.
`action.json` is its exact action.

The fixture proves deterministic offline verification. It does not represent a production
transaction, production signer or blockchain anchor.

`x402-sandbox-v0.3.0.json` records a hosted no-secret compatibility probe against the official x402
test facilitator. It proves advertised Base Sepolia exact support and rejection of a deliberately
invalid signature. It does not represent a funded settlement.

`kya-os/` records reproducible v0.4.0 delegated authority evidence using deterministic public test
identities. It proves the local cryptographic and binding path only. Verify it with
`pnpm evidence:kya:verify`.

`pulse-ap2-x402-v0.3/` preserves the independently generated 80 case Pulse AP2 x402 v0.3
reproduction record, its SHA256 digest, the exact official checker output and the immutable manual
workflow run metadata. It proves only the pinned offline conformance result described in that
directory.
