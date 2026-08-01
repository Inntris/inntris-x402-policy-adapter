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
