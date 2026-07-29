# Generated JSON schemas

The JSON schemas are generated from the runtime Zod schemas:

```bash
pnpm schemas:generate
```

CI regenerates them and fails if the committed output changes. Runtime validation remains the
authoritative enforcement path.
