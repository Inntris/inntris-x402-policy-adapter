# Contributing

## Development setup

Use Node.js `24.18.0` and pnpm `10.18.1`.

```bash
pnpm install --frozen-lockfile
pnpm format:check
pnpm lint
pnpm typecheck
pnpm test
pnpm conformance
pnpm evidence:verify
```

## Protocol changes

Treat action fields, hash preimages, reason codes, decision fields and key-registry fields as public
contracts.

1. Add a new version rather than silently changing an existing preimage.
2. Preserve historical fixture verification.
3. Update Zod schemas, generated JSON schemas, documentation and negative vectors together.
4. Add explicit invariant tests.
5. Keep rail binding and execution logic in its rail package. Register only the strict, versioned
   protocol-reference variant needed for the shared action and decision schemas in `decision-core`.

## Pull requests

Keep changes focused. Explain the threat addressed, compatibility impact, tests added and any
residual risk. Never include credentials or production signing material.

## Dependency updates

Dependabot may group minor and patch development-tool updates. Review major upgrades separately so
their compatibility changes, migrations and complete validation remain visible.
