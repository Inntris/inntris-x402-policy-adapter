# Inntris Decision Envelope and x402 Policy Adapter

> Inntris does not move money. It proves that the exact payment was authorised by organisational
> policy before another system moves it.

This repository is a public Phase 1 reference implementation of a rail-independent Inntris Decision
Envelope and a fail-closed adapter for the official x402 TypeScript SDK.

Inntris evaluates organisational policy, signs an immutable `ALLOW`, `BLOCK` or `REQUIRE_APPROVAL`
decision, binds it to the exact proposed payment and lets a separate executor consume that decision
once before settlement.

## What this repository proves

1. The same logical action has the same RFC 8785 canonical hash.
2. Any relevant payment change produces a different action or x402 requirements hash.
3. A signed decision can be verified without an Inntris account, API, database or blockchain node.
4. `BLOCK`, `REQUIRE_APPROVAL`, expired, tampered and replayed decisions cannot reach the injected
   settlement function.
5. A successful decision consumption is single use, while a retry with the same execution reference
   is idempotent.

## Product boundary

Inntris:

1. Evaluates organisational policy.
2. Binds the result to the exact proposed action.
3. Signs decisions with Ed25519.
4. Supports local, offline verification.
5. Fails closed before settlement.

Inntris does not hold funds, issue wallets, sign payment transactions, settle payments, act as a
facilitator or replace x402. It does not require Base anchoring for decision validity.

## Five minute quick start

Prerequisites:

1. Node.js `24.18.0`, the pinned active LTS release.
2. pnpm `10.18.1`.
3. Python `3.12` for the optional AP2 runtime gate and its official SDK.

The Node version is enforced, so `pnpm install` stops with `ERR_PNPM_UNSUPPORTED_ENGINE` on any
other release. Install the pinned version first if `node --version` disagrees with `.node-version`:

```bash
nvm install && nvm use          # or: fnm use --install-if-missing
```

Then:

```bash
corepack enable
corepack prepare pnpm@10.18.1 --activate
pnpm install --frozen-lockfile
pnpm demo
```

The demo runs eight scenarios without paid services:

```text
Scenario 1: ALLOW; signature valid; decision consumed; settlement permitted
Scenario 2: BLOCK; AMOUNT_EXCEEDS_TRANSACTION_LIMIT; DECISION_NOT_ALLOW; settlement not called
Scenario 3: REQUIRE_APPROVAL; HUMAN_APPROVAL_REQUIRED; DECISION_NOT_ALLOW; settlement not called
Scenario 4: ACTION_HASH_MISMATCH; settlement not called
Scenario 5: NONCE_ALREADY_CONSUMED; settlement not called
Scenario 6: DECISION_EXPIRED; settlement not called
Scenario 7: human approval issues a superseding ALLOW; original decision unchanged; settlement permitted
Scenario 8: APPROVAL_ALREADY_RESOLVED; no second decision issued
```

## Architecture

```mermaid
sequenceDiagram
    participant Agent
    participant Resource as x402 Resource Server
    participant Guard as Inntris x402 Guard
    participant Inntris as Inntris Decision Service
    participant Facilitator

    Agent->>Resource: Request paid resource
    Resource-->>Agent: 402 Payment Required
    Agent->>Guard: Proposed payment + purpose
    Guard->>Inntris: Evaluate exact action
    Inntris-->>Guard: Signed ALLOW/BLOCK decision
    Guard->>Guard: Verify signature, hash, expiry and nonce
    alt Valid ALLOW
        Guard->>Guard: Consume decision
        Guard->>Facilitator: Settle payment
        Facilitator-->>Guard: Settlement result
    else BLOCK or invalid
        Guard-->>Agent: Payment prevented
    end
```

The execution boundary is the component that calls the facilitator or payment rail. A decision is
evidence, not execution authority, until that executor verifies and consumes it.

See [ARCHITECTURE.md](ARCHITECTURE.md) for trust boundaries and the fingerprint preimage.

## Packages

| Package                           | Responsibility                                                                         |
| --------------------------------- | -------------------------------------------------------------------------------------- |
| `@inntris/decision-core`          | Strict schemas, JCS, SHA 256 hashes, Ed25519, stable reason codes and replay contracts |
| `@inntris/policy-engine`          | Versioned policy parsing, deterministic evaluation and the local provider              |
| `@inntris/postgres-store`         | Durable decisions, atomic approvals, consumption and cumulative spend                  |
| `@inntris/decision-verifier`      | Offline verification library and `inntris-verify` CLI                                  |
| `@inntris/x402-adapter`           | Official x402 type binding, remote provider and fail-closed settlement guard           |
| `@inntris/mtp-authority`          | Composed MTP authority, safe execution retries and recoverable consumption ordering    |
| `@inntris/a2a-settlement-gate`    | Finality, consumption, delegate idempotency and signed receipts for paid A2A tasks     |
| `@inntris/ap2-runtime-gate`       | Official AP2 mandate verification, policy binding, replay control and signed receipts  |
| `@inntris/wallet-signing-gate`    | Exact EVM transaction binding, decision consumption, injected signing and broadcast    |
| `@inntris/multi-rail-conformance` | One policy and verifier across x402, AP2, EVM, mock card and paid MCP                  |
| `@inntris/demo-api`               | Fastify reference API, key discovery, verification and consumption                     |

The adapter pins `@x402/core` `2.20.0`. It imports `PaymentRequirements` and `PaymentPayload` from
`@x402/core/types` and validates them with the official runtime schemas.

## Human approval and supersession

A signed decision is never mutated. `REQUIRE_APPROVAL` is an immutable statement that policy needed
a human, and it can never reach settlement.

Resolving the approval issues a **new** signed decision whose `supersedes_decision_id` references
the original:

```text
REQUIRE_APPROVAL decision (immutable, never consumable)
        ↓ POST /v1/decisions/approve
Current policy re-evaluated at resolution time
        ↓
New signed ALLOW or BLOCK decision, supersedes_decision_id set
        ↓
Verified, consumed once, then settled
```

Because policy is re-evaluated when the approval is resolved, a human grant cannot override a policy
that now denies the same action: a breached limit still produces a signed `BLOCK`. A refused
approval produces a signed `BLOCK` carrying `HUMAN_APPROVAL_REFUSED`. Resolution is single use, so a
repeat returns `APPROVAL_ALREADY_RESOLVED`.

The approval window is `approval.request_ttl_seconds` (default 900), measured from the original
decision's `issued_at` and independent of the much shorter `decision_ttl_seconds`.

## Durable PostgreSQL state

`@inntris/postgres-store` implements the local provider's atomic policy state contract. It persists
immutable decisions, claims each approval once and commits nonce consumption with the cumulative
spend increment in one PostgreSQL transaction. The daily limit is rechecked under the database write
lock, so two independently issued decisions cannot overrun the limit concurrently.

The in-memory stores remain the default for the zero-configuration demo. A production deployment
must inject `PostgresPolicyStateStore` or another implementation with equivalent durability and
transaction semantics. See [`packages/postgres-store/README.md`](packages/postgres-store/README.md).

The same package provides `PostgresMtpAuthorityStateStore`. It checkpoints the signed MTP request,
short-lived approval token, stable execution reference, MTP consumption receipt and completed local
consumption. The approval token is never logged and the table must be restricted to the runtime
service and migration roles.

## Existing MTP authority

`@inntris/mtp-authority` composes two independent controls without creating a second public decision
format. The signed Decision Envelope remains the exact, offline-verifiable x402 policy proof. MTP
adds registered-agent policy, trust, rate and spend controls.

For an automatic local `ALLOW`, the provider signs an MTP `sig_version: 3` request whose payload
contains the complete `inntris-action-v1`, action hash, decision ID, decision fingerprint and policy
identity. It returns the Decision Envelope only after MTP approves and the bridge state is durable.

At execution it claims one reference, consumes MTP, persists the MTP receipt, consumes the local
decision with the same reference and only then allows the x402 guard to settle. A lost MTP response
is retried safely. A changed reference, malformed receipt, sandbox token or unavailable service
fails closed.

Enable this mode on the reference API with:

```text
INNTRIS_POSTGRES_URL
INNTRIS_MTP_API_URL
INNTRIS_MTP_AGENT_ID
INNTRIS_MTP_SIGNING_SEED_BASE64URL or INNTRIS_MTP_SIGNING_SEED_FILE
INNTRIS_MTP_SIGNING_KEY_ID
INNTRIS_MTP_POLICY_HASH optional
```

MTP mode requires the PostgreSQL migrations and a dedicated registered MTP agent key. Startup
rejects reuse of the Decision Envelope signing key. The first composite release covers automatic
`ALLOW` decisions; cross-service human approval recovery is deliberately not exposed yet.

See [`packages/mtp-authority/README.md`](packages/mtp-authority/README.md) and
[`docs/MTP_COMPATIBILITY.md`](docs/MTP_COMPATIBILITY.md).

## A2A settlement gate

The follow-on `@inntris/a2a-settlement-gate` package imports the official A2A 1.0 `Task` type from
`@a2a-js/sdk` `1.0.0`. A2A does not define payment submission or settlement finality states, so the
package exposes those as explicit Inntris adapter interfaces.

The gate binds the exact x402 payment to the A2A task, context and resource. It requires a verified
Inntris `ALLOW`, confirms the configured settlement finality, reverifies and consumes the decision,
claims one delegate execution and signs an action receipt. `PAYMENT_SUBMITTED`, `UNKNOWN`, failed,
malformed or mismatched settlement evidence never reaches the delegate.

See [`packages/a2a-settlement-gate/README.md`](packages/a2a-settlement-gate/README.md).

## AP2 runtime gate

The `@inntris/ap2-runtime-gate` package verifies autonomous AP2 Checkout and Payment Mandate chains
with the pinned official AP2 Python SDK. It verifies the merchant checkout JWT, open mandate
constraints, key binding, expiry, amount, currency, merchant, payee and checkout reference. It then
binds the verified mandate hashes to an Inntris action and applies the current organisational
policy. Protocol validity does not override a policy block or approval requirement.

AP2 0.2 represents autonomous intent through open Checkout and Payment Mandates rather than a
separate Intent Mandate. The package commits both open mandate hashes into an explicit intent
verification hash. TypeScript does not reimplement AP2 cryptography.

See [`packages/ap2-runtime-gate/README.md`](packages/ap2-runtime-gate/README.md).

## EVM wallet signing gate

The `@inntris/wallet-signing-gate` package canonicalises the complete unsigned EVM transaction and
binds it to an `evm` Decision Envelope. It verifies and consumes an `ALLOW` decision before calling
an injected wallet. Inntris never receives the wallet key. An atomic execution claim prevents a
second decision from signing and broadcasting the same unsigned transaction.

See [`packages/wallet-signing-gate/README.md`](packages/wallet-signing-gate/README.md).

## Multi-rail conformance

Run `pnpm conformance` to evaluate x402, AP2, EVM, mock corporate card and paid MCP actions through
one policy provider and one offline verifier. Every rail must produce the same top-level Decision
Envelope contract, and an exact action mutation must invalidate the original decision.

See [`packages/multi-rail-conformance/README.md`](packages/multi-rail-conformance/README.md).

## Verify the committed evidence offline

```bash
pnpm build
node packages/decision-verifier/dist/cli.js decision evidence/allow.json \
  --action evidence/action.json \
  --keys fixtures/keys/registry.json \
  --expected-policy-version 1 \
  --at 2026-07-29T09:30:30.000Z
```

Expected result:

```text
PASS schema
PASS decision fingerprint
PASS Ed25519 signature
PASS action hash
PASS decision binds the supplied action
PASS decision expiry at supplied execution time
PASS policy version
PASS x402 payment-requirements binding

VERDICT: ALLOW
DECISION: VALID
```

Other commands:

```bash
node packages/decision-verifier/dist/cli.js hash-action fixtures/actions/allow.json
node packages/decision-verifier/dist/cli.js hash-policy policies/demo-x402-policy.yml
node packages/decision-verifier/dist/cli.js inspect evidence/allow.json
```

The CLI makes no network request by default. A remote registry is only used when the operator
explicitly supplies `--keys-url`.

## Run the reference API

Normal startup never creates a signing key. Generate an explicit development key:

```bash
pnpm keys:generate:dev
```

Then set either `INNTRIS_SIGNING_SEED_BASE64URL` or `INNTRIS_SIGNING_SEED_FILE` and run:

```bash
pnpm demo:api
```

For a disposable local demonstration, explicitly opt into the public fixture identity:

```powershell
$env:INNTRIS_DEMO_MODE = "true"
pnpm demo:api
```

The service exposes:

| Method | Path                             | Purpose                     |
| ------ | -------------------------------- | --------------------------- |
| `GET`  | `/healthz`                       | Non-secret health state     |
| `GET`  | `/.well-known/inntris-keys.json` | Public Ed25519 key registry |
| `POST` | `/v1/decisions/evaluate`         | Signed policy decision      |
| `POST` | `/v1/decisions/verify`           | Local verification result   |
| `POST` | `/v1/decisions/approve`          | Resolve a human approval    |
| `POST` | `/v1/decisions/consume`          | Single-use consumption      |

A valid policy `BLOCK` is an HTTP `200` response. HTTP errors represent technical failure, invalid
input, authentication failure or replay conflict.

## Live Inntris mode

`RemoteInntrisDecisionProvider` uses:

```text
INNTRIS_API_URL
INNTRIS_API_KEY
INNTRIS_KEY_REGISTRY_URL
INNTRIS_EXPECTED_POLICY_VERSION
```

It validates the complete response, verifies the signature locally and fails closed when the service
or registry is unavailable. It never falls back to a local allow decision. The example is in
`examples/remote-inntris`.

If the current Inntris production API has a different wire contract, place a translation adapter in
front of this provider. Do not change production endpoints solely to match this repository.

## Decision and money canonicalisation

`InntrisActionV1` rejects unknown fields except the explicit top-level `extensions` object. Monetary
values are decimal strings with at least two fractional digits and no redundant trailing zeroes
beyond the second digit. Therefore `4.50` is valid while `4.5` and `4.500` are rejected.

x402 atomic-unit amounts are converted using the configured asset decimal count. The exact original
x402 requirements remain bound through `payment_requirements_hash`, so conversion does not weaken
the challenge binding.

See [docs/DECISION_ENVELOPE.md](docs/DECISION_ENVELOPE.md) for the complete signed-data contract.

## Security and evidence

1. [THREAT_MODEL.md](THREAT_MODEL.md) documents attacks, mitigations and residual risk.
2. [SECURITY.md](SECURITY.md) documents safe key handling and vulnerability reporting.
3. [docs/EVIDENCE_VERIFICATION.md](docs/EVIDENCE_VERIFICATION.md) explains independent review.
4. [docs/MTP_COMPATIBILITY.md](docs/MTP_COMPATIBILITY.md) distinguishes this envelope from existing
   MTP request hashes and evidence packs.
5. `fixtures/decisions` contains all committed positive and negative test vectors.

## Development commands

```bash
pnpm format:check
pnpm lint
pnpm typecheck
pnpm test:unit
pnpm test:integration
pnpm test:ap2-official
pnpm conformance
pnpm build
pnpm evidence:verify
pnpm audit --prod --audit-level high
```

## Known limitations

1. The default stores remain in-memory reference implementations. The optional PostgreSQL store
   supplies durable decisions, atomic approval claims and atomic consumption with spend accounting,
   but deployments still need database provisioning, backups, access controls and monitoring.
2. Generic consumption cannot be atomic with every external payment rail. The executor must retain
   the same execution reference, use facilitator idempotency and reconcile a consume-success,
   settlement-unknown outcome.
3. Legacy split `NonceStore` and `SpendState` implementations cannot make consumption and spend
   atomic. Production cumulative limits must use `AtomicPolicyStateStore`; the PostgreSQL
   implementation also rechecks the daily limit during consumption to prevent concurrent overruns.
4. The public fixture signing identity is intentionally known and must never be used in production.
5. No claim is made about HSM custody, disaster recovery, production latency, blockchain finality or
   a live hosted deployment.
6. The `v0.2.0` release includes the reference A2A, AP2, EVM wallet and conformance packages. It is
   not evidence that a production service is deployed.
7. The AP2 reference gate uses a local Python process and a pinned official SDK revision. Production
   packaging, monitored process isolation and SDK upgrade governance remain operator work.
8. Card and paid MCP lanes are mock conformance fixtures, not production card-network or MCP billing
   integrations.

## Licence

MIT, preserving the licensing decision already present when this repository was created.
