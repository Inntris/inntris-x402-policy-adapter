# Official x402 sandbox validation

The repository uses the no-signup x402 Foundation test facilitator at
`https://x402.org/facilitator`. The probe calls it through the pinned official `@x402/core` SDK.

Run:

```bash
pnpm test:x402-sandbox
```

The probe performs two non-settling checks:

1. The facilitator's schema-validated `/supported` response must advertise x402 v2 `exact` on Base
   Sepolia, `eip155:84532`.
2. The facilitator's `/verify` endpoint must reject a structurally valid payment containing a
   deliberately invalid EIP 3009 signature.

The probe never calls `/settle`, holds no buyer key and moves no test or mainnet asset. A scheduled
workflow repeats it weekly without repository secrets. Override the endpoint only with an explicit
HTTPS URL:

```bash
INNTRIS_X402_FACILITATOR_URL=https://example.test/facilitator pnpm test:x402-sandbox
```

## Real settlement boundary

A successful testnet settlement requires a dedicated buyer key and funded Base Sepolia USDC. Keep
that key in a secret manager or the CI secret store, never in Git, chat, fixtures or normal logs.
The first funded run should use the smallest representable amount, a dedicated receiving address and
the same execution reference for Inntris consumption and facilitator reconciliation.

This public probe proves current protocol connectivity, advertised compatibility and rejection of an
invalid payment. It does not claim a successful onchain settlement or production facilitator
availability.
