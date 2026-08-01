# Phase 1 final report

## Outcome

Phase 1 is implemented in the public `Inntris/inntris-x402-policy-adapter` repository. Pull request
[#1](https://github.com/Inntris/inntris-x402-policy-adapter/pull/1) introduced the Inntris Decision
Envelope, local policy engine, offline verifier, x402 adapter, reference API, evidence, tests and
documentation. Pull request [#8](https://github.com/Inntris/inntris-x402-policy-adapter/pull/8)
refreshed and immutably pinned the GitHub Action dependencies.

The repository now uses the requested `inntris-x402-policy-adapter` slug. The default branch is
protected by an active ruleset requiring pull requests, linear history, resolved review
conversations, current required checks and CodeQL scanning. Deletions and force pushes are blocked.

The existing MIT licence was retained because the build brief allowed an existing Inntris licensing
decision to take precedence over the Apache 2.0 default.

## Delivered boundary

Inntris evaluates organisational policy and signs an immutable decision bound to the exact proposed
payment. The x402 guard verifies and consumes a valid `ALLOW` decision before it permits an injected
settlement function to run.

Inntris does not hold funds, issue wallets, sign transactions, settle payments, act as a
facilitator, or depend on blockchain anchoring for decision validity.

## Validation commands

The following commands were run with Node.js `24.18.0` and pnpm `10.18.1`:

```text
pnpm install --frozen-lockfile
pnpm format:check
pnpm lint
pnpm typecheck
pnpm test:unit
pnpm test:integration
pnpm test
pnpm build
pnpm demo
pnpm evidence:verify
pnpm schemas:generate
pnpm evidence:generate
pnpm audit --prod --audit-level high
gitleaks git --staged --redact --no-banner --no-color --verbose
```

A clean clone also ran the frozen install, build, 34 test baseline, demo and evidence verification.
The final suite contains 36 passing tests after adding API authentication and rate limiting
regressions.

GitHub Actions ran the following successfully on the final Phase 1 head and on `main`:

```text
quality
secret-scan
CodeQL analyse
CodeQL security gate
```

The executable demo proved:

```text
ALLOW permits one consumed settlement
BLOCK prevents settlement
REQUIRE_APPROVAL prevents settlement
payee substitution prevents settlement
different-reference replay prevents settlement
expiry prevents settlement
```

The offline evidence verifier passed schema, fingerprint, Ed25519 signature, action hash, expiry,
policy version and x402 payment requirements binding checks. The production dependency audit
reported no known vulnerabilities. Gitleaks reported no leaks.

## Files created

Pull request #1 created these 118 files:

```text
.env.example
.gitattributes
.github/dependabot.yml
.github/workflows/ci.yml
.github/workflows/codeql.yml
.gitignore
.node-version
.npmrc
.nvmrc
.prettierignore
.prettierrc.json
ARCHITECTURE.md
CONTRIBUTING.md
SECURITY.md
THREAT_MODEL.md
apps/demo-api/package.json
apps/demo-api/src/app.ts
apps/demo-api/src/index.ts
apps/demo-api/src/start.ts
apps/demo-api/tsconfig.json
docs/API.md
docs/DECISION_ENVELOPE.md
docs/EVIDENCE_VERIFICATION.md
docs/MTP_COMPATIBILITY.md
eslint.config.mjs
evidence/README.md
evidence/action.json
evidence/allow.json
examples/local-x402/package.json
examples/local-x402/src/demo.ts
examples/local-x402/tsconfig.json
examples/remote-inntris/package.json
examples/remote-inntris/src/example.ts
examples/remote-inntris/tsconfig.json
fixtures/README.md
fixtures/actions/allow.json
fixtures/actions/block.json
fixtures/actions/require-approval.json
fixtures/decisions/expired-decision.json
fixtures/decisions/replayed-decision.json
fixtures/decisions/stale-policy-version.json
fixtures/decisions/tampered-amount.json
fixtures/decisions/tampered-network.json
fixtures/decisions/tampered-payee.json
fixtures/decisions/tampered-policy-hash.json
fixtures/decisions/tampered-verdict.json
fixtures/decisions/unknown-signing-key.json
fixtures/decisions/valid-allow.json
fixtures/decisions/valid-block.json
fixtures/decisions/valid-require-approval.json
fixtures/decisions/x402-challenge-mismatch.json
fixtures/keys/registry.json
fixtures/manifest.json
fixtures/policies/demo.json
package.json
packages/decision-core/README.md
packages/decision-core/package.json
packages/decision-core/src/canonical.ts
packages/decision-core/src/decision.ts
packages/decision-core/src/demo.ts
packages/decision-core/src/index.ts
packages/decision-core/src/metrics.ts
packages/decision-core/src/provider.ts
packages/decision-core/src/schemas.ts
packages/decision-core/src/signing.ts
packages/decision-core/tsconfig.json
packages/decision-verifier/README.md
packages/decision-verifier/package.json
packages/decision-verifier/src/cli.ts
packages/decision-verifier/src/index.ts
packages/decision-verifier/src/io.ts
packages/decision-verifier/src/verify.ts
packages/decision-verifier/tsconfig.json
packages/policy-engine/README.md
packages/policy-engine/package.json
packages/policy-engine/src/evaluate.ts
packages/policy-engine/src/index.ts
packages/policy-engine/src/local-provider.ts
packages/policy-engine/src/policy.ts
packages/policy-engine/tsconfig.json
packages/x402-adapter/README.md
packages/x402-adapter/package.json
packages/x402-adapter/src/binding.ts
packages/x402-adapter/src/guard.ts
packages/x402-adapter/src/index.ts
packages/x402-adapter/src/remote-provider.ts
packages/x402-adapter/tsconfig.json
pnpm-lock.yaml
pnpm-workspace.yaml
policies/README.md
policies/demo-x402-policy.yml
schemas/README.md
schemas/inntris-action-v1.schema.json
schemas/inntris-decision-v1.schema.json
schemas/inntris-key-registry-v1.schema.json
schemas/inntris-policy-v1.schema.json
scripts/package.json
scripts/src/generate-dev-key.ts
scripts/src/generate-evidence.ts
scripts/src/generate-schemas.ts
scripts/src/verify-evidence.ts
scripts/tsconfig.json
test/helpers.ts
test/integration/api.test.ts
test/integration/fixtures.test.ts
test/tsconfig.json
test/unit/canonical.test.ts
test/unit/consumption.test.ts
test/unit/metrics.test.ts
test/unit/policy-evaluation.test.ts
test/unit/policy-gate.test.ts
test/unit/signing-verifier.test.ts
test/unit/x402-remote.test.ts
tsconfig.base.json
tsconfig.json
vitest.config.ts
vitest.integration.config.ts
vitest.unit.config.ts
```

Pull request #1 also replaced the placeholder contents of `README.md`. Pull request #8 updated
`.github/workflows/ci.yml` and `.github/workflows/codeql.yml`. This report adds `FINAL_REPORT.md`.

## Unresolved limitations

1. The reference policy, spend and consumption stores are in memory. Production use needs durable,
   distributed state.
2. The generic provider interface cannot make decision consumption and an external settlement
   transaction atomic. A production integration needs a rail-specific reservation, outbox or
   reconciliation design.
3. The included signer supports environment, mounted file and injected-provider loading, but no
   production HSM or managed key service integration is claimed.
4. The committed signing identity is deliberately public and only suitable for fixtures and the
   local demo.
5. The remote provider implements and verifies the proposed Inntris API contract, but this work did
   not verify a hosted production Inntris decision endpoint.
6. Reference API limits are process local. A production deployment needs a distributed limit at its
   trusted ingress.
7. No claims are made for disaster recovery, blockchain finality, HSM-grade custody or Base
   anchoring as a root of trust.
8. The packages are workspace packages and were not published to npm in Phase 1.
9. This report originally scoped A2A, AP2, wallet and multi-rail work into separate issues. Current
   `main` implements the A2A, AP2 and EVM wallet packages. Full multi-rail conformance remains in
   [#5](https://github.com/Inntris/inntris-x402-policy-adapter/issues/5).
