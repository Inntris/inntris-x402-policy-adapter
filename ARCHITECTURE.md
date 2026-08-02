# Architecture

## Design objective

The adapter creates portable proof that organisational policy authorised one exact proposed payment.
It keeps policy evaluation, evidence verification and payment settlement separate.

## Trust boundaries

1. The agent and x402 challenge are untrusted input.
2. The Inntris decision provider is trusted to evaluate policy but its response is still verified
   locally.
3. The key registry is an explicit trust root selected by the verifier or operator.
4. The nonce store is trusted to provide atomic single-use consumption.
5. The payment executor is the final enforcement boundary.
6. The facilitator and settlement rail remain outside Inntris.
7. A remote signing broker is a separate custody boundary. Its output is untrusted until locally
   verified against the operator-selected public key registry.

## Module boundaries

```mermaid
flowchart LR
    X["Official x402 SDK types"] --> A["@inntris/x402-adapter"]
    A --> C["@inntris/decision-core"]
    P["@inntris/policy-engine"] --> C
    V["@inntris/decision-verifier"] --> C
    API["Fastify demo API"] --> P
    API --> V
    API --> MS["@inntris/managed-signing"]
    MS --> KMS["Operator signing broker and managed key"]
    MS --> C
    A --> E["Injected settlement executor"]
    T["Official A2A Task type"] --> G["@inntris/a2a-settlement-gate"]
    G --> A
    G --> S["Injected settlement and finality provider"]
    G --> D["Injected delegate executor"]
    M["Official AP2 Python SDK"] --> R["@inntris/ap2-runtime-gate"]
    R --> C
    R --> Q["Injected AP2 payment delegate"]
    W["@inntris/wallet-signing-gate"] --> C
    W --> V
    W --> K["Injected EVM wallet"]
    W --> B["Injected transaction broadcaster"]
    N["@inntris/multi-rail-conformance"] --> A
    N --> R
    N --> W
    N --> V
    X402["x402 executor"] --> H["@inntris/mtp-authority"]
    H --> P
    H --> MTP["Existing MTP verify and token authority"]
    H --> PG["Durable MTP bridge state"]
```

`decision-core` has no x402 dependency. Rail-specific packages construct a common `InntrisActionV1`,
while the decision and verifier remain rail independent.

The wallet gate treats the injected wallet as a separate trust boundary. It passes the exact
canonical transaction to `signTransaction`, then parses the returned RLP bytes with viem, recovers
the signer and compares every transaction field before any broadcast.

The conformance package adds mock card and paid MCP bindings without adding execution authority. It
uses the same policy engine, Decision Envelope and verifier as the production-oriented rail gates.

## Action hash

The authoritative action hash is:

```text
"sha256:" + lowercase_hex(SHA-256(RFC8785_JCS(InntrisActionV1)))
```

The strict schema is applied before canonicalisation. The action includes principal, agent, rail,
transaction, resource, scheme and both available x402 digests.

## Policy hash

YAML or JSON is parsed and validated first. The policy hash covers the resulting object, not the
source text:

```text
"sha256:" + lowercase_hex(SHA-256(RFC8785_JCS(validated_policy_object)))
```

Comments, indentation and mapping order therefore do not change the policy hash.

## Decision fingerprint and signature

Circular hashing is avoided with two explicit preimages:

1. Construct the decision without `decision_fingerprint` and without `signing.signature`.
2. Include `signing.alg` and `signing.key_id`.
3. JCS canonicalise that fingerprint payload and calculate the SHA 256 fingerprint.
4. Insert `decision_fingerprint`.
5. JCS canonicalise the complete decision without `signing.signature`.
6. Sign those bytes with Ed25519.
7. Insert the base64url signature.

The signed decision is immutable. A human approval produces a new decision whose
`supersedes_decision_id` points to the earlier `REQUIRE_APPROVAL` decision. The provider
re-evaluates current organisational policy when the approval is resolved, so the superseding
decision is a signed `BLOCK` whenever policy now denies the same action. Resolution is single use
and is bounded by `approval.request_ttl_seconds` rather than by the decision TTL.

The signing provider can hold an in-process development seed or call the managed signing broker. The
managed path sends only the canonical signing payload, its SHA 256 digest and the requested key
identity. The response is accepted only after local Ed25519 verification. Key rotation uses a static
provider selected at startup plus a registry that preserves old public keys and validity windows. A
controlled restart makes the cutover atomic from the application's point of view.

## Evaluation precedence

1. Invalid structure is a technical error.
2. Explicit deny entries.
3. Network, asset, payee, resource and purpose restrictions.
4. Per-transaction limits.
5. Daily cumulative limits.
6. Time restrictions.
7. Human approval thresholds.
8. Explicit merchant allow.
9. Default block.

A deny always overrides approval or allow.

## Settlement gate

The guard follows this order:

```text
validate x402 challenge
construct exact action
request decision
validate decision schema
verify fingerprint and Ed25519 signature
recalculate action hash
check policy version and expiry
require ALLOW
consume decision
call injected settlement function
```

Every failure stops before settlement. There is no fallback allow path.

## A2A settlement and delegate gate

The A2A package treats the official A2A task ID and context ID as binding inputs. Its
`PAYMENT_SUBMITTED` and settlement states are Inntris adapter contracts, not A2A protocol task
states.

```text
validate A2A task and submitted payment binding
construct the x402 action with a signed-hash A2A extension
request and locally verify the Inntris decision
require ALLOW
settle or confirm the configured finality
reject PAYMENT_SUBMITTED, UNKNOWN, failed or mismatched evidence
reverify the decision after settlement confirmation
consume the decision
claim one delegate execution
execute the delegate
sign the task, payment, settlement and result receipt
```

Settlement uses a deterministic idempotency key. Delegate execution uses a separate atomic claim. A
completed retry returns the stored receipt and result. An unresolved prior delegate claim pauses
instead of risking a second side effect.

## Consumption and partial failure

First consumption succeeds. A retry using the same execution reference returns the original
consumption success. A different reference is a replay conflict.

`AtomicPolicyStateStore` also commits the daily spend increment in the consumption transaction. The
PostgreSQL implementation locks the cumulative spend row through its atomic upsert and rechecks the
daily limit there. Decisions can therefore be evaluated concurrently without allowing their later
consumption to overrun the shared limit. A rejected limit check rolls the nonce insert back.

No generic library can make a database nonce write atomic with every external facilitator. A
production executor must use the same execution reference as the facilitator idempotency key and
reconcile an unknown settlement outcome instead of creating a new execution.

When MTP composition is enabled, the execution sequence is MTP consumption, durable MTP receipt
checkpoint, local Decision Envelope consumption, then settlement. A lost MTP response is retried
with the same reference and returns the original receipt. A process stop after the checkpoint
resumes local consumption. MTP is placed first because a rejected secondary authority must not
consume local daily spend. A local rejection after MTP consumption leaves a non-settled authority
receipt for reconciliation but cannot move funds.

The A2A gate deliberately places consumption after confirmed settlement and before delegate
execution. This protects the paid task rather than using a payment submission as authority. A
production deployment still needs durable execution state and reconciliation when a process fails
after claiming the delegate or after the delegate returns but before the receipt is stored.

## AP2 mandate and runtime gate

The AP2 gate delegates mandate cryptography to the official AP2 Python SDK pinned by commit. In the
autonomous AP2 0.2 flow, open Checkout and Payment Mandates represent intent. Closed Checkout and
Payment Mandates bind the merchant checkout JWT and the exact transaction.

```text
validate the mandate presentation
resolve trusted issuer and merchant public keys
verify both mandate chains and the checkout JWT with the official AP2 SDK
require current expiry and exact merchant, payee, amount, currency and checkout bindings
bind all verified mandate hashes to the Inntris AP2 action
request and locally verify the current Inntris policy decision
require ALLOW and consume the decision
atomically claim the Payment Mandate hash for the exact execution
execute the AP2 delegate
sign and store the action receipt
```

An AP2 valid mandate remains non executable when current organisational policy returns `BLOCK` or
`REQUIRE_APPROVAL`. The default in memory execution store is a reference implementation only.

## Observability

The metrics abstraction records:

```text
decisions_total{verdict,rail}
decision_latency_ms
verification_failures_total{reason}
replay_attempts_total
```

Fastify logs structured request, decision, verdict, rail, reason, latency, verification and
consumption fields. API keys, bearer tokens, signing seeds and complete payment credentials are not
logged.
