# Inntris x402 adapter security review

- **Target:** `@inntris/x402-adapter` `0.4.0` and the decision, policy and reconciliation packages
  it depends on.
- **Base commit:** `a3e28e1`
- **Date:** 2026-08-17
- **Method:** executable adversarial test suite, `test/security/x402-attack-matrix.test.ts`.
- **Reproduce:** `pnpm test:security` (writes `evidence/x402-security-review.json`).

## Result

Ten attack classes were tested. **Five pass outright, five pass only under a stated precondition,
and four findings were recorded.**

| #   | Attack class                                   | Verdict                | Primary control                                   |
| --- | ---------------------------------------------- | ---------------------- | ------------------------------------------------- |
| 1   | Recipient substitution                         | **PASS**               | Policy payee allowlist + action-hash binding      |
| 2   | Asset substitution                             | **PASS**               | Policy asset allowlist + action-hash binding      |
| 3   | Amount substitution                            | **PASS**, with **F-1** | Policy limits + action-hash binding               |
| 4   | Network substitution                           | **PASS**               | Policy network allowlist + action-hash binding    |
| 5   | Expired authorisation                          | **PASS**               | Decision expiry checked at guard and at provider  |
| 6   | Nonce / replay                                 | **PASS**, with **F-2** | Single-use nonce + execution reconciliation       |
| 7   | Insufficient balance                           | **PASS**, with **F-3** | Facilitator verification + fail-closed settlement |
| 8   | Facilitator `verify=true`, settlement failure  | **PASS**, with **F-3** | Execution reconciliation, no automatic retry      |
| 9   | Repeated resource access after one payment     | **PASS**               | Single-use nonce consumption                      |
| 10  | Payment requirement vs signed payment mismatch | **PASS**, with **F-4** | `accepted` / requirements hash equality           |

Findings, in the order they should be fixed:

| ID  | Finding                                                                                      | Severity   | Status                             |
| --- | -------------------------------------------------------------------------------------------- | ---------- | ---------------------------------- |
| F-1 | `assetDecimals` is caller-supplied, so an atomic amount can be rescaled below a policy limit | **High**   | Open, exploitable via the HTTP API |
| F-2 | With no reconciliation store, an identical retry settles a second time                       | **High**   | Open, default configuration        |
| F-3 | The guard does not require facilitator verification before settlement                        | **Medium** | Open, ordering is convention only  |
| F-4 | The inner signed authorisation is hash-bound but never cross-checked                         | **Medium** | Open, facilitator compensates      |

**The suite is green.** A green run means every recorded behaviour was observed, including the four
findings — the finding tests assert the current, weaker behaviour so it is locked against silent
change. Do not read a passing suite as "no findings"; read the table above.

## What was actually exercised

The attacks are not run against `InntrisX402Guard` in isolation. `test/security/harness.ts` builds a
minimal x402-protected resource server (`GuardedResourceServer`) wired in the documented order —
authorise under policy, ask the facilitator to verify, settle behind the guard, then release the
resource — together with a deterministic `FakeFacilitator` whose default verification only accepts a
payload whose signed EIP-3009 authorisation pays the quoted recipient the quoted amount. Each attack
is asserted on three observable outcomes: the reason codes returned, whether the settlement executor
was invoked, and whether the resource was released.

The decision provider is the real `LocalPolicyDecisionProvider` signing real Ed25519 decisions
against `policies/demo-x402-policy.yml` (per-transaction limit `100.00`, daily `500.00`, human
approval above `75.00`, 60-second decision TTL, `eip155:8453` and `USDC` only). No verification step
is stubbed.

## Per-attack evidence

### 1. Recipient substitution — PASS

Two paths were tested. A direct authorisation request for `payTo` = `0x…00ff` returned a signed
`BLOCK` carrying `PAYEE_NOT_ALLOWED`. Separately, a legitimate `ALLOW` for the merchant address was
then presented for settlement with the payee swapped to the attacker address; the guard raised
`InntrisGuardError` with `ACTION_HASH_MISMATCH`, `DECISION_BINDING_MISMATCH` and
`PAYMENT_REQUIREMENTS_MISMATCH`, and **the settlement executor was never called**.

### 2. Asset substitution — PASS

Direct request for `asset` = `DAI`: signed `BLOCK` with `ASSET_NOT_ALLOWED`. Post-authorisation
swap: `InntrisGuardError` with `ACTION_HASH_MISMATCH`, `DECISION_BINDING_MISMATCH`,
`PAYMENT_REQUIREMENTS_MISMATCH`; settlement not invoked.

### 3. Amount substitution — PASS, with finding F-1

Direct request for `150000000` atomic units (150.00 USDC, above the 100.00 limit): signed `BLOCK`
with `AMOUNT_EXCEEDS_TRANSACTION_LIMIT`. Post-authorisation swap from the quoted 4.50 to a larger
amount: `InntrisGuardError`, settlement not invoked.

The nominal case holds. **F-1 defeats it** — see below.

### 4. Network substitution — PASS

Direct request on `eip155:84532`: signed `BLOCK` with `NETWORK_NOT_ALLOWED`. Post-authorisation
swap: `InntrisGuardError`, settlement not invoked.

Networks are CAIP-2 identifiers with no alias handling in `@x402/core` 2.20.0 — `base` and
`base-sepolia` are rejected at schema parse rather than silently canonicalised — so there is no
alias-confusion variant of this attack.

### 5. Expired authorisation — PASS

A valid `ALLOW` was held past its 60-second TTL (clock advanced 61 s). Settlement was refused with
`DECISION_EXPIRED`, and an independent direct consumption attempt was refused with
`DECISION_EXPIRED` by the provider. The facilitator was never called and the resource was not
served. Expiry is enforced in two places — `verifyDecision` in the guard and
`LocalPolicyDecisionProvider.consume` — so an integration that skips the guard's verification still
cannot consume an expired decision.

### 6. Nonce / replay — PASS, with finding F-2

Consumption semantics are correct: first consumption `consumed`; a retry with the **same** execution
reference is `idempotent` and preserves the original `consumed_at`; a **different** execution
reference is a `conflict` with `NONCE_ALREADY_CONSUMED`.

With a reconciliation store configured, full settlement replay is closed in both directions: reusing
the execution reference gives `EXECUTION_ALREADY_COMPLETED`, inventing a new one gives
`NONCE_ALREADY_CONSUMED`, and the facilitator settled exactly once for one resource release.

Without a reconciliation store — the default — this does not hold. See **F-2**.

### 7. Insufficient balance — PASS, with finding F-3

Balance is the facilitator's judgement, not the adapter's. Two timings were tested.

Discovered at verification: the facilitator returned `isValid: false` /`insufficient_funds`, the
integration refused, settlement was never invoked and the resource was not served.

Discovered at settlement: the settlement call failed after being attempted. The guard raised
`EXECUTION_OUTCOME_UNKNOWN`, the resource was not served, and exactly one operation was left in
`listUnresolved()` with status `outcome_unknown` awaiting authoritative resolution. That is the
correct fail-closed shape — the adapter does not assume a failed call means no money moved.

The first path depends on the integration choosing to call verify. See **F-3**.

### 8. Facilitator `verify=true` then settlement failure — PASS, precondition in F-3

The strongest result in the review. With verification passing and settlement then failing:

- the first attempt raised `EXECUTION_OUTCOME_UNKNOWN` after exactly one settlement call;
- the automatic retry was refused with the same code **without calling the facilitator again**;
- the resource was never served;
- the operation remained unresolved with `lastErrorCode: SettlementFailure`, visible to operators
  via `listUnresolved()` and the `/v1/operations/unresolved` endpoint.

With `classifySettlementError` returning `failed_final`, the same sequence produced
`EXECUTION_FAILED_FINAL` on both attempts, one settlement call, no resource release.

An unknown outcome is therefore never converted into either a silent success or a silent retry. This
is the property that matters most for double-spend exposure, and it holds.

### 9. Repeated resource access after one payment — PASS

Three accesses were attempted with one `ALLOW`. The first was served; the second and third were
refused with `NONCE_ALREADY_CONSUMED`. One settlement call, one resource release.

Scope note: the adapter guarantees _one settled authorisation per decision_. Whether the resource
server also caches or re-serves already-purchased content to the same agent is outside the adapter
and was not assessed.

### 10. Payment requirement vs signed payment mismatch — PASS, with finding F-4

A payload whose `accepted` block named a different `payTo` than the requirements being charged was
rejected at authorisation with `X402BindingError` ("The payment payload is bound to different x402
payment requirements"), and at settlement with `PAYMENT_REQUIREMENTS_MISMATCH`; settlement was never
invoked.

Attaching a payload _after_ a payload-free authorisation is also caught: `payment_payload_hash`
moves from `null` to a hash, the action hash changes, and settlement is refused with
`ACTION_HASH_MISMATCH`.

The `accepted` block is bound exactly. The signed authorisation inside it is not. See **F-4**.

---

## Findings

### F-1 — `assetDecimals` is caller-supplied, rescaling the amount policy evaluates

**Severity: High. Exploitable through the shipped HTTP API.**

`actionFromX402` converts the x402 atomic-unit `amount` into the decimal figure policy reasons about
using `input.assetDecimals`, a parameter supplied by the caller rather than derived from the asset:

```
atomic 150000000 @ assetDecimals=6  -> "150.00"   BLOCK  AMOUNT_EXCEEDS_TRANSACTION_LIMIT
atomic 150000000 @ assetDecimals=9  -> "0.15"     ALLOW
atomic 150000000 @ assetDecimals=12 -> "0.00015"  ALLOW
```

The same on-chain transfer of 150 USDC is blocked or allowed depending on a number the caller chose.
The resulting decision is **internally consistent** — action hash, decision binding and
`payment_requirements_hash` all agree, `verifyBeforeSettlement` returns valid, and the transfer
settles. An offline verifier cannot detect the rescaling without independently knowing the asset's
true precision, which nothing in the envelope carries.

The test drives this end to end: the understated decision reaches settlement and the resource is
released (`evidence/x402-security-review.json`, id `A3-F1`).

This is not only an integrator footgun. `apps/demo-api/src/app.ts` accepts `asset_decimals` from the
**request body** on `POST /v1/kya/x402/evaluate`:

```ts
asset_decimals: z.number().int().min(0).max(18),
```

So the party asking for authorisation chooses the precision that its own limits are checked against.
Every per-transaction, daily and human-approval threshold in `policies/demo-x402-policy.yml` is
bypassable by declaring a larger precision.

**Recommended fix.** Derive precision from the asset rather than accepting it. Add an asset registry
keyed on `(network, asset)` that carries decimals, reject any `(network, asset)` pair not in the
registry, and remove `assetDecimals` from every externally reachable request schema. As an interim
mitigation, pin `asset_decimals` server-side per configured asset and ignore the client value. As a
defence in depth, carry the atomic amount and the declared decimals inside the signed action so an
offline verifier can recompute the conversion.

### F-2 — Without a reconciliation store, an identical retry settles a second time

**Severity: High. Present in the default configuration.**

`reconciliationStore` is optional on `InntrisX402Guard`. When it is omitted, `settleIfAuthorised`
treats an `idempotent` nonce consumption as a successful consumption and proceeds:

```ts
const consumption = await this.consumeBeforeExecution(decision, executionRef);
if (!consumption.success) {
  /* blocked */
}

if (reconciliation === undefined) {
  return settle(); // second call for the same execution reference
}
```

Replaying the same `(decision, executionRef)` pair therefore invokes the settlement executor again.
The test observes **two settlement calls and two resource releases for one authorisation**
(`evidence/x402-security-review.json`, id `A6-F2`). The nonce store is doing exactly what it is
specified to do — an identical retry is idempotent _at the consumption layer_ — but nothing else
stands between that answer and a second payment.

`README.md` limitation 2 already pushes this onto the executor ("use facilitator idempotency"), so
the risk is acknowledged in prose. It is not enforced in code, and the safe configuration is the one
you have to opt into.

**Recommended fix.** Make `reconciliationStore` required for `settleIfAuthorised`, or refuse to
settle on an `idempotent` consumption when no store is configured and raise
`RECONCILIATION_REQUIRED`. If the optional form is kept for compatibility, the constructor should
require an explicit acknowledgement flag and the guard should emit a warning, so no deployment
reaches production unaware.

### F-3 — Verify-before-settle is convention, not structure

**Severity: Medium.**

`settleIfAuthorised` accepts an opaque `settle: () => Promise<T>` and has no facilitator seam and no
notion of a verification result. An integration that calls settle without first calling the
facilitator's `/verify` is not stopped by anything in the adapter. The test demonstrates settlement
completing while the facilitator's `verify` was never invoked (`evidence/x402-security-review.json`,
id `A7-A8-F3`).

This matters because the adapter's defence against F-4, against insufficient balance, and against a
forged or expired EIP-3009 signature is _entirely_ the facilitator's verification step. The primary
sequence diagram in `README.md` goes `Consume decision -> Settle payment` and does not depict a
verify call at all, so an integrator following the main documentation will build the unsafe order.

**Recommended fix.** Offer a `settleVerified` entry point that takes a facilitator client and
performs verify-then-settle itself, so the safe order is the easy one. At minimum, add the verify
step to the README sequence diagram and state that the guard does not perform payment verification.

### F-4 — The inner signed authorisation is hash-bound but never cross-checked

**Severity: Medium. Compensating control exists.**

Every policy field in the action is derived from the payload's `accepted` block. The `payload`
member that carries the actual signed EIP-3009 authorisation is typed `Record<string, unknown>` by
`@x402/core` and is bound only as an opaque hash. Nothing compares `payload.authorization.to`
against `accepted.payTo`, `payload.authorization.value` against `accepted.amount`, or
`payload.authorization.validBefore` against the decision's own expiry.

The test constructs a payload whose `accepted` block matches the quoted requirements exactly, while
the signed authorisation pays `0x…00ff` a value of `1`. The adapter issued a fully valid `ALLOW`
naming payee `0x…0001` and amount `4.50`, and `verifyBeforeSettlement` returned `valid: true`
(`evidence/x402-security-review.json`, id `A10-F4`). Only the facilitator rejected it, with
`invalid_exact_evm_payload_recipient_mismatch`.

The compensating control is real: a correct facilitator will not settle such a payment. But it means
an Inntris `ALLOW` attests to _what was quoted_, not to _what was signed_ — and combined with F-3,
nothing structurally guarantees the facilitator is consulted.

**Recommended fix.** Add scheme-aware cross-checks for the `exact` EVM scheme before the action is
built: assert `authorization.to == accepted.payTo`, `authorization.value == accepted.amount`, and
that `validBefore` is not earlier than the decision expiry. Fail closed on any `exact`-scheme
payload that does not parse. Until then, state the limitation explicitly rather than describing the
payload as "bound".

---

## What this review does not cover

1. **No live settlement.** The facilitator is a deterministic fake. No on-chain transaction, no
   funded testnet wallet, no real `/settle` call. The existing `pnpm test:x402-sandbox` probe covers
   live facilitator connectivity and `/verify` rejection only.
2. **No cryptographic review of Ed25519 signing or RFC 8785 canonicalisation.** Both are exercised
   by the existing 168-test unit suite; neither was independently audited here.
3. **KYA OS authority, AP2, A2A, EVM, card and MCP rails** were not assessed. This review is x402
   only. F-1 reaches the KYA x402 endpoint because that endpoint accepts `asset_decimals`, but the
   KYA delegation and proof logic itself was not tested.
4. **No concurrency testing.** All attacks are sequential. Race conditions between consumption and
   settlement across processes, and the atomicity claims of `PostgresExecutionReconciliationStore`,
   were not exercised.
5. **In-memory stores only.** The PostgreSQL store was not run.
6. **No transport-level testing.** Authentication, rate limiting and TLS on the demo API were not
   assessed.
7. **Resource-server behaviour beyond the adapter** — caching, session reuse, content re-delivery to
   an already-paid agent — is out of scope, as noted under attack 9.

## Claims this evidence supports

Defensible today:

- "Inntris blocks recipient, asset, amount and network substitution against a signed policy
  decision, and refuses to settle any payment that differs from the one authorised."
- "An expired decision cannot settle and cannot be consumed."
- "A decision is single-use. One authorisation yields at most one settled payment."
- "When a facilitator verifies a payment and settlement then fails or times out, Inntris fails
  closed: the resource is not released, no automatic retry occurs, and the operation is recorded for
  reconciliation."
- "Every check is reproducible offline from a signed decision, with no Inntris account or API."

Not defensible until the findings are closed:

- Any unqualified claim that Inntris **enforces spend limits**. F-1 makes limits bypassable by a
  caller-chosen precision value that the shipped API accepts from the request body.
- Any claim of **double-spend prevention** without naming the reconciliation store as a requirement.
  F-2 means the default configuration re-settles an identical retry.
- Any claim that Inntris **validates the payment** or **binds the signed payment**. F-4 means it
  binds the quoted requirements and hashes the payload; the facilitator validates the signature, the
  recipient and the balance.
- Any claim of **end-to-end x402 settlement assurance**. No live settlement was performed.

## Reproduction

```bash
nvm use 24            # engines require Node >= 24.18.0 < 25
pnpm install --frozen-lockfile
pnpm test:security    # 18 tests; writes evidence/x402-security-review.json
pnpm test:unit        # 168 pre-existing tests, unchanged by this review
```

`evidence/x402-security-review.json` records, for every attack, the expectation, the observed
behaviour, the reason codes returned, whether the settlement executor ran and whether the resource
was released.
