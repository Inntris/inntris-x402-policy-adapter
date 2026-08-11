# Generated JSON schemas

The JSON schemas are generated from the runtime Zod schemas:

```bash
pnpm schemas:generate
```

CI regenerates them and fails if the committed output changes. Runtime validation remains the
authoritative enforcement path.

The A2A binding, payment submission, settlement observation and action receipt schemas are generated
from the runtime schemas exported by `@inntris/a2a-settlement-gate`.

The AP2 mandate presentation, official verification evidence and action receipt schemas are
generated from the runtime schemas exported by `@inntris/ap2-runtime-gate`.

The EVM unsigned transaction and wallet gate input schemas are generated from the runtime schemas
exported by `@inntris/wallet-signing-gate`.

The mock card authorisation and paid MCP tool-call input schemas are generated from the conformance
bindings exported by `@inntris/multi-rail-conformance`.

The execution operation schema is generated from the durable reconciliation record exported by
`@inntris/execution-reconciliation`.

The KYA authority policy, normalised binding, strict payment request and top level presentation
wrapper schemas are generated from `@inntris/kya-os-authority`. Raw KYA credentials and proofs are
validated by the pinned `@kya-os/mcp` package and are intentionally not copied into Inntris schemas.
