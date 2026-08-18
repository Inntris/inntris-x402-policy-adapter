# Inntris x402 Adapter — Security Review

**Status:** `EXECUTED — BASELINE FROZEN (round 3). No product code changed in this round.`
**Reference standard:** Wang, Yang, Chen, Ji, Payer. _When HTTP 402 Meets the Blockchain: Risks on
Emerging x402 Payments._ USENIX Security '26. arXiv:2607.19545v1 [cs.CR], 21 Jul 2026. **Secondary
references:** arXiv:2605.11781 (_Five Attacks on x402 Agentic Payment Protocol_); arXiv:2605.30998
(_Free-Riding the Agentic Web_); Coinbase x402 specification v1 and v2. **Reviewed artefact:**
`inntris/inntris-x402-policy-adapter` — baseline commit recorded in §7. **Reviewer:** Claude Code,
under the round-1 to round-3 audit briefs. **Date executed:** 2026-08-18.

---

## 0. Rule of evidence

> **No cell in the results table may be marked PASS without an attached artefact.** An artefact is
> an HTTP request/response pair, a chain receipt, a test log, or a source file and line range. A
> test with no artefact is `NOT TESTED`, never `PASS`. A test whose outcome is ambiguous is
> `AMBIGUOUS`, never `PASS`.

This rule exists because the value of this document to a customer or an investor is entirely a
function of whether it can survive someone re-running it. A PASS asserted from reading the code,
rather than from exercising it, is worth less than no document at all — it converts an engineering
gap into a credibility gap.

The USENIX authors state the same limit on their own results: an SR pass means the target passed the
implemented checks, not that it is generally secure. This review inherits that limitation and states
it wherever results are summarised.

---

## 1. Scope and role declaration

This is the load-bearing section. Everything downstream depends on it being accurate.

### 1.1 What the paper's rules govern

The paper distils eight security rules (SR1–SR8) for **facilitators** — the party that receives a
payment payload plus the declared requirements, returns a verification verdict, and then constructs,
signs, sponsors and broadcasts the settlement transaction. It separately derives two rules for the
**resource server** (merchant), governing when the protected resource may be released.

| Role                       | Rules that govern it        |
| -------------------------- | --------------------------- |
| Facilitator                | SR1–SR8                     |
| Resource server / merchant | Server-SR1, Server-SR2      |
| Client / payer agent       | Not addressed by this paper |

### 1.2 What the Inntris adapter is

The adapter is a policy-decision and settlement-gate library that a resource server or executor
embeds. It evaluates organisational policy over a proposed x402 payment, signs an immutable `ALLOW`
/ `BLOCK` / `REQUIRE_APPROVAL` decision bound to that exact payment, and wraps the caller's
settlement call in `InntrisX402Guard.settleIfAuthorised`, which verifies and single-use-consumes the
decision before invoking a caller-supplied executor closure. It holds no payer key, constructs,
signs, sponsors and broadcasts no transaction, and reads no chain. It does not itself issue the 402
challenge, and it does not call a facilitator's `/verify` or `/settle` — the integrator does both,
and passes the settlement call in as an opaque closure (`guard.ts:154`). It gates the resource
response only indirectly: it gates the settlement executor, and the caller is expected to release
the resource only after `settleIfAuthorised` returns.

- [x] **Resource-server middleware.** The adapter sits in front of a protected resource, issues the
      402 challenge, forwards proofs to a third-party facilitator, gates the response, and emits
      signed receipts. It signs no settlement transaction and sponsors no gas. → **SR1–SR8 do not
      govern it. Server-SR1/SR2 do.**

**Two deviations from that box, stated rather than glossed.** The adapter does _not_ issue the 402
challenge and does _not_ forward proofs to a facilitator; both remain the integrator's. This matters
for the review because it makes every server-side obligation **conventional rather than
structural**: the guard gates the executor, not the HTTP response, so a caller that releases the
resource without calling `settleIfAuthorised`, or that calls it without first calling `/verify`, is
not stopped by anything in the adapter. See F-3 and the `Nature` column in
`docs/security/D3_RULE_TO_CODE_MAP.md`.

### 1.3 Rule applicability matrix

Each rule is assigned exactly one disposition. `ENFORCED` means the adapter must reject;
`RE-DERIVED` means the adapter must independently reach its own conclusion rather than accept the
facilitator's, and must record disagreement; `N/A` means the adapter is structurally incapable of
violating or satisfying the rule.

| Rule       | Substance (paraphrased)                                                                                                         | Disposition for Inntris                                  | Justification                                                                                                                                                                                                                                                                                             |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SR1        | Verification must reject a proof that does not match the server-declared requirements                                           | RE-DERIVED                                               | The adapter declares the requirements. It can and must check the binding itself rather than trust a remote verdict. **Resolved: partially met.** JSON-field binding is re-derived on the library path (`binding.ts:78`, `guard.ts:165`); the EIP-712 domain is not, and the HTTP path re-derives nothing. |
| SR2        | Verification must reject authorization that is not authentic under the intended signature model                                 | RE-DERIVED                                               | Signature recovery is cheap and local. Delegating it entirely is an unforced dependency. **Resolved: not met.** `ABSENT` — no signature recovery anywhere; `payload` is opaque. Owner `FACILITATOR`.                                                                                                      |
| SR3        | Verification must reject expired authorization                                                                                  | RE-DERIVED                                               | Clock comparison is local. **Resolved: split.** Inntris _decision_ expiry is re-derived in two independent places (`verify.ts:195`, `local-provider.ts:246`). The _authorisation's_ own `validBefore`/`validAfter` are never read.                                                                        |
| SR4        | Settlement must report valid only when settled on chain                                                                         | RE-DERIVED                                               | _This is the single most important row._ **Resolved: not met.** `ABSENT` — no chain client, no RPC, no confirmation depth. The guard treats any executor return that does not throw as success and never inspects the returned value. Demonstrated by E2 and E3. Owner `FACILITATOR`.                     |
| SR5        | Verification must fail fast on non-settleable or economically meaningless proofs, and enforce idempotency and a freshness bound | PARTIAL — idempotency ENFORCED, settleability RE-DERIVED | **Resolved: idempotency met but configuration-dependent** (`provider.ts:98/110`), and absent entirely when no reconciliation store is configured (F-2). **Settleability and the freshness bound are `ABSENT`.**                                                                                           |
| SR6        | Sponsored execution must be bounded by configurable fee/gas/compute caps                                                        | N/A                                                      | **Structural:** the adapter holds no payer key and constructs no transaction. Its only settlement seam is `settle: () => Promise<T>` at `guard.ts:154`, an opaque caller-supplied closure. It cannot sponsor anything because it cannot build anything.                                                   |
| SR7        | Re-verify immediately before settlement submission                                                                              | N/A as written; analogue **ENFORCED**                    | The adapter does not submit. Its analogue — re-verifying immediately before the executor runs — is met: `guard.ts:156` re-verifies and `guard.ts:165` re-compares the action hash within `settleIfAuthorised`. Only _decision_ freshness is re-checked, not authorisation freshness.                      |
| SR8        | Settle only proofs whose on-chain execution semantics are explicitly allowed and unambiguous                                    | N/A                                                      | **Structural:** the adapter constructs no transaction and inspects no calldata. Note the corollary rather than a comfort: because `payload` is opaque to it, an ERC-6492 wrapper carrying an attacker-chosen factory and calldata passes through unexamined to the facilitator (D7).                      |
| Server-SR1 | Release the protected resource only after settlement succeeds under the acceptance criteria                                     | **ENFORCED**, conditionally and conventionally           | Primary obligation. Met on the library path with a reconciliation store configured; `CONVENTIONAL` because the guard gates the executor rather than the response. "Settlement succeeds" means the executor did not throw — see SR4.                                                                       |
| Server-SR2 | If verification succeeds but settlement fails, roll back post-verification effects and treat the request as unpaid              | **ENFORCED**, conditionally                              | Primary obligation. Met with a reconciliation store (E4, A8): resource withheld, nonce spent, operation left unresolved. With no store — the default — the raw executor error propagates with no reason code and no record (A7-late-nostore).                                                             |

> Any `N/A` must be justified by a structural fact about the adapter, never by "we don't do that
> yet." A roadmap item is not a scope boundary.

### 1.4 Threat model

Adapted from §3.1 of the paper, narrowed to the adapter's position.

**In scope**

- **Malicious client.** Submits arbitrary, mutated, replayed or concurrent payment proofs to obtain
  the protected resource without a settled payment, or to induce a false attestation.
- **Faulty or non-compliant facilitator.** Not malicious, but buggy or permissive — returns
  `isValid: true` for proofs that will not settle, or reports settlement success for a transaction
  that reverted, was dropped, or was never broadcast. The paper found every one of the 15
  facilitators it evaluated violated at least one rule, so this is the expected case, not the edge
  case.
- **Malicious server.** A counterparty deployment that crafts requirements to induce a misleading
  Inntris receipt.

**Out of scope, stated so nobody infers a claim**

- Fully malicious or colluding facilitator. This is a trust-failure model, not a compliance model.
  The adapter's mitigation is independent chain confirmation (SR4 row above), not detection of
  facilitator intent.
- Payer wallet compromise, key theft, client-side agent prompt injection.
- Business logic beyond the payment boundary.
- Chain reorganisation deeper than the configured confirmation depth. **There is no configured
  depth: the adapter performs no chain read at any depth.** Reorganisation is therefore out of scope
  in the strongest possible sense — the adapter would not observe one. This is SR4's consequence,
  not a scoping choice.

---

## 2. Results summary

| Severity      | Count            | Findings                                                                         |
| ------------- | ---------------- | -------------------------------------------------------------------------------- |
| Critical      | 3                | F-5, F-6, F-9                                                                    |
| High          | 3                | F-1, F-2, F-7                                                                    |
| Medium        | 3                | F-3, F-4, F-8                                                                    |
| Low           | 0                | —                                                                                |
| Informational | 0                | —                                                                                |
| Not tested    | 11 register rows | A9, B3, B4, B5, C4, D2, D3, R7, plus the surface listed in `D7:untested-surface` |

**Machine-readable results:** `evidence/x402-security-review.json`, 86 cases — 59 `PASS`, 2
`BORROWED`, 23 `KNOWN_GAP`, 2 `NOT_TESTED`. Every case carries its expectation, observed behaviour,
rejection layer, and results against both facilitator stand-ins. Digest and reproduction in §7.

**Ownership, from D1.** Of the 22 attack-matrix cases: 14 owned by Inntris, 2 `INNTRIS_CONTAINMENT`,
2 `FACILITATOR` (borrowed), 4 owned by nobody.

**Read this before the tables.** A `PASS` here means the adapter rejected the case under the
implemented checks, in the configuration named. It is not a general security claim, and three
structural results below (SR2, SR4, SR5-settleability all `ABSENT`) mean the composite's safety
rests on the facilitator for those rules. The reference study found rule violations in every one of
the 15 facilitators it evaluated.

**Severity definitions**

| Level         | Definition                                                                                                                                       |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| Critical      | An attacker obtains the protected resource without a settled payment, **or** Inntris signs a receipt attesting to a payment that did not settle. |
| High          | An attacker reliably obtains repeated resource access from one authorisation, or induces a receipt that materially misstates the payment.        |
| Medium        | Rejection happens, but at the wrong layer or without evidence capture; failure is not attested.                                                  |
| Low           | Correct behaviour with weak or absent logging, or a configuration default that is unsafe but overridable.                                        |
| Informational | Deviation from the reference standard with no exploit path in the current deployment.                                                            |

---

## 3. Test register — protocol conformance

Ten tests were requested. Nine were added: they close gaps between the requested set and the attack
paths the reference paper actually validated. Additions are marked ⊕ with the reason.

Legend for **Result**: `PASS` / `FAIL` / `AMBIGUOUS` / `N/A` / `NOT TESTED`.

### Group A — Requirement-to-payload binding (SR1)

| ID   | Test                                                                                                                          | Rule     | Expected                                                            | Result                                        | Evidence                                                                                                                                                                                                                                                                                                                                     |
| ---- | ----------------------------------------------------------------------------------------------------------------------------- | -------- | ------------------------------------------------------------------- | --------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A1   | Recipient substitution — `authorization.to` ≠ `payTo`, re-signed by the payer key                                             | SR1      | Reject before any facilitator call                                  | **FAIL**                                      | Case `A10-F4`. The adapter issued a valid `ALLOW` naming payee `0x…01` and amount `4.50` for a payload whose signed authorisation pays `0x…ff` a value of `1`; `verifyBeforeSettlement` returned valid. Under the permissive stand-in the resource was released. Only the compliant facilitator rejected it. Owner `FACILITATOR`.            |
| A2   | Asset substitution — token contract differs from declared `asset`                                                             | SR1      | Reject                                                              | **PASS**                                      | Cases `A2a` (`BLOCK`, `ASSET_NOT_ALLOWED`, `INNTRIS_PREFLIGHT`) and `A2b` (post-authorisation swap rejected `INNTRIS_POST_VERIFY`, settlement never invoked, holds under the permissive stand-in). Binds the _declared_ asset field; whether the signature is over that token is A5.                                                         |
| A3   | Amount substitution — under-payment **and** over-payment                                                                      | SR1      | Reject both; over-payment is not a silent pass in an `exact` scheme | **PASS**, with F-1 and F-6 attached           | Cases `A3a`/`A3b`. Any change to the amount changes the requirements hash and is rejected at settlement in both directions. But the adapter binds the requirements _it is given_: on the HTTP path it never learns the price actually served (F-6), and the decimal figure policy evaluates is rescalable by the caller (F-1, case `A3-F1`). |
| A4   | Network substitution — `network` field mismatch (v1 string / v2 CAIP-2)                                                       | SR1      | Reject                                                              | **PASS**                                      | Cases `A4a`/`A4b`. CAIP-2 only; `base` and `base-sepolia` aliases are rejected at schema parse (`D7:network-families`), so there is no alias-confusion variant.                                                                                                                                                                              |
| A5 ⊕ | **EIP-712 domain substitution** — signature valid for the same nominal amount on a different `chainId` or `verifyingContract` | SR1, SR2 | Reject                                                              | **FAIL** _(by construction, not by exercise)_ | No signature recovery exists: `payload` is `Record<string, unknown>` and is hashed without inspection. `D3` records SR1-domain and SR2 as `ABSENT`; `D2` records `payload.signature` as validated against nothing. The adapter cannot reject this case because it never reads the domain.                                                    |
| A6 ⊕ | **Scheme substitution** — `exact` swapped for `deferred` or an unknown scheme                                                 | SR1      | Reject                                                              | **FAIL**                                      | Case `D7:scheme-allowlist`. `exact`, `deferred`, `upto` and `totally-made-up` all parse and reach a decision. `D2:unevaluated-fields-in-receipt` shows `scheme: "deferred"` producing a valid signed `ALLOW`. No policy rule references scheme.                                                                                              |
| A7 ⊕ | **Cross-resource substitution** — a proof valid for resource A presented at resource B                                        | SR1      | Reject                                                              | **FAIL**                                      | `D2` row `paymentPayload.resource.url`: the payload's own resource URL is bound into the payload hash but never compared with the `resource` field policy evaluates. A payload minted for resource A carries into a decision for resource B without objection.                                                                               |
| A8 ⊕ | **v2 `accepted` echo trust** — `paymentPayload.accepted` mutated to disagree with the server's own requirements               | SR1      | Reject; the adapter must bind against its own requirements record   | **PASS**                                      | Case `A10`. `binding.ts:78` compares the payload's `accepted` hash against the requirements the adapter holds and raises `X402BindingError` before any facilitator call — `INNTRIS_PREFLIGHT` under both stand-ins. `D4` integrity mutations: 6 of 6 rejected here.                                                                          |
| A9 ⊕ | **v2 extensions tampering** — client deletes or overwrites server-supplied extension info                                     | SR1      | Reject                                                              | **NOT TESTED**                                | The adapter carries `extensions` into the action hash (`D2` row) but no server-supplied extension contract is modelled anywhere in the repository, so there is nothing to tamper with. Recorded rather than inferred.                                                                                                                        |
| A10  | Mismatched requirement vs signed payment (aggregate case)                                                                     | SR1      | Reject                                                              | **PASS**                                      | Cases `A10` and `A10-late`. Attaching a payload after a payload-free authorisation moves `payment_payload_hash` from `null` and is rejected with `ACTION_HASH_MISMATCH`; settlement never invoked; holds under the permissive stand-in.                                                                                                      |

**Why A5 is separate from A4.** A4 mutates a JSON string; A5 mutates the cryptographic domain the
payer actually signed over. An adapter that string-compares `network` and stops there will pass A4
and fail A5. The paper's distinction between integrity mutations and binding mutations is exactly
this line.

**Why A8 exists.** In x402 v2 the payment payload carries an `accepted` object echoing the
requirements the client claims it was served. That object is client-supplied. An adapter that binds
against it is binding against attacker-controlled data.

### Group B — Authorization authenticity (SR2)

| ID   | Test                                                                                                                    | Rule     | Expected                                                                         | Result                                    | Evidence                                                                                                                                                                                                                                                                                                                                  |
| ---- | ----------------------------------------------------------------------------------------------------------------------- | -------- | -------------------------------------------------------------------------------- | ----------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| B1 ⊕ | **Signature integrity mutation** — bytes flipped, no re-signing                                                         | SR2      | Reject                                                                           | **FAIL**                                  | `D2` row `paymentPayload.payload.signature`: validated against nothing. `D4` binding mutations mutate the signature and the adapter issues a decision over it regardless — the mutated bytes simply change the payload hash. Rejection, when it happens, is the facilitator's.                                                            |
| B2 ⊕ | **Signer substitution** — `authorization.from` ≠ recovered signer                                                       | SR2      | Reject                                                                           | **FAIL** _(by construction)_              | Nothing recovers a signer, so `from` cannot be compared with anything. `D3` SR2 = `ABSENT`.                                                                                                                                                                                                                                               |
| B3 ⊕ | **Signature malleability** — high-`s` variant of a valid signature                                                      | SR2      | Reject or normalise; must not create a second accepted form of one authorisation | **NOT TESTED**                            | There is no signature handling to malleate against. Recording a FAIL would imply a check exists and mis-handles the variant; it does not exist at all. The consequence is covered by B1/B2.                                                                                                                                               |
| B4   | ERC-1271 contract-wallet signature, where the validator's verdict differs between off-chain call and on-chain execution | SR2, SR8 | Reject, or mark unsupported                                                      | **N/A** _(structural)_, with a correction | Case `D7:contract-signatures`. The adapter is structurally incapable of judging contract signatures: `payload` is opaque to it. But "unsupported" would overstate — it does not reject them either. It hashes them and passes them through to the facilitator unexamined. State it that way, never as "contract wallets are unsupported". |
| B5   | ERC-6492 wrapper carrying attacker-chosen factory address and calldata                                                  | SR2, SR8 | Reject, or mark unsupported                                                      | **N/A** _(structural)_, same correction   | Case `D7:contract-signatures`. A 6492-shaped signature was carried into the action hash without inspection. The reference paper's only validated asset-theft finding ran through 6492 handling; that handling is entirely the facilitator's here, and was not exercised.                                                                  |

**B4/B5 disposition.** If the adapter does not parse contract-signature payloads, mark both `N/A`
and state that contract wallets are unsupported. Do not leave them blank — the paper's only
validated asset-theft finding ran through ERC-6492 handling, and silence here reads as an untested
claim.

### Group C — Freshness and replay (SR3, SR5, SR7)

| ID   | Test                                                                                                        | Rule         | Expected                                              | Result                                | Evidence                                                                                                                                                                                                                                                                                                                                                                              |
| ---- | ----------------------------------------------------------------------------------------------------------- | ------------ | ----------------------------------------------------- | ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| C1   | Expired authorisation — `validBefore` in the past                                                           | SR3          | Reject                                                | **FAIL**                              | Case `D5:validBefore`, and `D5:F7-unevaluated-not-detectable` where a payload whose `validBefore` is `1` produced a valid signed `ALLOW`. The authorisation's own expiry is never read. **Do not confuse this with the Inntris decision TTL, which is enforced — see C6.**                                                                                                            |
| C2 ⊕ | **Premature authorisation** — `validAfter` far in the future                                                | SR3          | Reject                                                | **FAIL** _(by construction)_          | `validAfter` is never read, for the same structural reason as C1. `D3` records the SR3 authorisation-window row as `ABSENT`.                                                                                                                                                                                                                                                          |
| C3   | Nonce replay, sequential — resubmit a proof already settled                                                 | SR3, SR5     | Reject                                                | **PASS**, configuration-dependent     | Cases `A6` (`NONCE_ALREADY_CONSUMED` on a second execution reference), `A6-recon` (`EXECUTION_ALREADY_COMPLETED` on a reused reference) and `A9` (three accesses, one release). Both hold under the permissive stand-in. **With no reconciliation store — the default — an identical retry settles a second time** (F-2, case `A6-F2`, and `D6` replay row).                          |
| C4 ⊕ | **Nonce race, concurrent** — N parallel requests carrying one proof, before the nonce is consumed           | SR5, SR7     | At most one release; all others rejected              | **NOT TESTED**                        | The suite is sequential. The in-memory nonce store's check-and-set is single-process and the atomic PostgreSQL store was not run. Recorded in `D7:untested-surface`. The reference paper's _validated_ free-shopping exploit was the concurrent case, so this is the highest-value untested row in the register.                                                                      |
| C5 ⊕ | **Remaining-validity threshold sweep** — measure the minimum accepted `validBefore − now`                   | SR5          | A stated, configured, defensible bound                | **FAIL** _(by construction)_          | There is no bound to measure. `maxTimeoutSeconds` is bound into the requirements hash and never compared to anything (`D2` row); `validBefore` is never read. `D3` records the SR5 freshness row as `ABSENT`.                                                                                                                                                                         |
| C6 ⊕ | **Verify-to-release delay** — inject latency between verification and the release decision, spanning expiry | SR7 analogue | Re-check freshness; do not release on a stale verdict | **PASS**, for decision freshness only | Case `A5`: the clock is advanced past the 60-second decision TTL between authorisation and release; settlement is refused with `DECISION_EXPIRED` at the guard _and_ independently at the provider, the facilitator is never called, and the resource is withheld. Holds under the permissive stand-in. It is the _decision's_ freshness that is re-checked, not the authorisation's. |

**C4 is not C3.** Sequential replay is the easy case, and it is the one most implementations already
handle. The paper's _validated_ free-shopping exploit was the concurrent case: verification is
stateless and does not reserve the nonce, so many parallel requests all pass before any settles.
Your original list had only the sequential form. This is the single most likely place for the
adapter to fail.

**C5 rationale.** Evaluated facilitators enforced thresholds of roughly 3–7 seconds, and the paper
notes that even compliant deployments see failures because the window is checked at verification
while execution happens later. Record the adapter's number; an unbounded or unconfigured threshold
is a finding.

### Group D — Settleability and economics (SR5)

| ID   | Test                         | Rule | Expected                  | Result                | Evidence                                                                                                                                                                                                                                                                                                                                 |
| ---- | ---------------------------- | ---- | ------------------------- | --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| D1   | Insufficient payer balance   | SR5  | Reject before release     | **FAIL** _(borrowed)_ | Case `A7`. Under a facilitator reporting `insufficient_funds` the resource is withheld — but the rejection is `FACILITATOR_VERIFY` and under the permissive stand-in **the resource is released**. Inntris holds no balance state and contributes nothing. Owner `FACILITATOR`. Severity is not survivable in isolation: see F-9 and E3. |
| D2 ⊕ | **Zero-amount proof**        | SR5  | Reject                    | **NOT TESTED**        | No settleability or economic-meaning check exists to exercise. A zero amount would pass the canonical-amount schema as `0.00` and be evaluated against limits, which it satisfies trivially. Recorded rather than asserted; not exercised.                                                                                               |
| D3 ⊕ | **Dust below fee threshold** | SR5  | Reject or flag per policy | **NOT TESTED**        | Same structural reason as D2. The adapter has no notion of fee cost.                                                                                                                                                                                                                                                                     |

### Group E — Verify/settle divergence (SR4, Server-SR1, Server-SR2)

**This group is the core of the review.** It is where the adapter's primary obligations live.

| ID   | Test                                                                                | Rule       | Expected                                           | Result                              | Evidence                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ---- | ----------------------------------------------------------------------------------- | ---------- | -------------------------------------------------- | ----------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| E1   | Facilitator returns `isValid: true`, settlement subsequently fails                  | Server-SR1 | Resource withheld                                  | **PASS**, configuration-dependent   | Case `A8`. One settlement call, `EXECUTION_OUTCOME_UNKNOWN`, the automatic retry refused **without re-calling the facilitator**, resource never served, operation left unresolved with `lastErrorCode: SettlementFailure`. With `classifySettlementError` returning `failed_final`, the same shape with `EXECUTION_FAILED_FINAL`. **With no reconciliation store the raw executor error propagates with no reason code and no record** (`A7-late-nostore`). |
| E2 ⊕ | **Settlement success with no transaction identifier**                               | SR4        | Treat as unsettled                                 | **FAIL**                            | Case `E2:no-transaction-identifier`. A facilitator answering `success` while naming no transaction had the resource released and the operation marked succeeded. `settleIfAuthorised` treats any executor return that does not throw as success and never inspects the returned value.                                                                                                                                                                      |
| E3 ⊕ | **Settlement success with a tx hash that reverted, was dropped, or does not exist** | SR4        | Independent chain confirmation; treat as unsettled | **FAIL**                            | Case `E3:unconfirmed-transaction`. A plausible but phantom transaction hash was accepted and the resource released. The adapter contains no chain client, no RPC configuration and no confirmation depth. **Inntris's notion of "settled" is the facilitator's JSON.**                                                                                                                                                                                      |
| E4   | Rollback of post-verification side effects when settlement fails                    | Server-SR2 | Effects reversed, request marked unpaid            | **PASS**, with a wording correction | Case `E4:rollback`. Resource withheld, operation left `outcome_unknown`, and the consumed nonce is _not_ returned — the authorisation is spent and the payer must obtain a new decision. Fail-closed and the correct direction, but it is a **withholding, not a reversal**: no compensating record is signed.                                                                                                                                              |
| E5   | Repeated resource access after one settled payment                                  | Server-SR1 | One authorisation, one release                     | **PASS**, configuration-dependent   | Case `A9`: three accesses on one decision, first served, second and third refused `NONCE_ALREADY_CONSUMED`, one settlement call, one release. Holds under the permissive stand-in. Subject to F-2 in the default configuration.                                                                                                                                                                                                                             |

**E3 is the difference between an evidence layer and a relay.** The paper documents a case where a
facilitator API reported settlement failure while the transaction had already been broadcast and
confirmed — the API response and the chain disagreed in _both_ directions. If the adapter's notion
of "paid" is the facilitator's JSON rather than a confirmed receipt at a stated depth, then Inntris
attests to what a third party said, not to what happened. That is a defensible product — but it must
be described that way, and it is not what the current positioning implies.

### Group F — Sponsored execution (SR6, SR8)

**`N/A`.** The adapter signs no settlement transaction and sponsors no gas or fees; SR6 and SR8 have
no attack surface here. This is structural, not a roadmap position: the adapter holds no payer key
and its only settlement seam is an opaque caller-supplied closure (`guard.ts:154`).

One corollary belongs here rather than being left implied. Because the adapter constructs nothing,
it also _inspects_ nothing: the `payload` member reaches the facilitator exactly as the client sent
it. SR8's attack surface is not absent from the system, only from Inntris. See B4/B5.

---

## 4. Test register — Inntris receipt integrity

Not derived from the paper. These are the tests specific to Inntris's own claim, and no external
standard covers them. They matter more than Group A commercially: Groups A–E establish that the
adapter is not worse than the ecosystem; Group R establishes whether the receipt means anything.

| ID  | Test                                                                                                                                            | Expected                                                                                                 | Result                               | Evidence                                                                                                                                                                                                                                                                                                                                                                                                                              |
| --- | ----------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- | ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| R1  | Does the receipt bind observed chain state — tx hash, chain id, block, confirmation depth, final status — or only the facilitator's assertion?  | Binds observed chain state, or the receipt schema explicitly labels the field as a third-party assertion | **FAIL**                             | It binds neither. `InntrisDecisionV1` carries no transaction identifier, block, depth or status field at all — the decision is issued _before_ settlement and is never amended. The settlement outcome lives only in an unsigned reconciliation row. E2 and E3 show the adapter accepts a facilitator's assertion without inspecting even the identifier it returns.                                                                  |
| R2  | Does the receipt bind the resource identifier and a digest of the payment requirements actually served?                                         | Yes; otherwise a receipt is portable across resources                                                    | **PASS**, with a caveat that matters | `protocol_reference.resource` and `protocol_reference.payment_requirements_hash` are both bound and both covered by the action hash and signature (`binding.ts:102`, verified in `A10`, `D5:amount-atomic`). The caveat: on the HTTP path the hash is computed by the caller, not over requirements the issuer served (F-6), so it is a digest of _asserted_ requirements.                                                            |
| R3  | Is a receipt emitted for a **failed or rejected** payment, and does it encode the failure unambiguously?                                        | Yes. A witness that only records successes is not a witness                                              | **FAIL**, split                      | Policy rejections _are_ signed: a `BLOCK` is a full signed decision carrying reason codes (cases `A1a`–`A4a`), so the corpus is not selected on that axis. But **settlement failures produce no signed record at all** — only an unsigned `outcome_unknown` row in the reconciliation store (`E4:rollback`, `A8`), and with no store configured, not even that (`A7-late-nostore`). The half that matters for attestation is missing. |
| R4  | Are the pre-execution policy decision and the post-settlement outcome distinct records, separately signed and separately timestamped?           | Yes                                                                                                      | **FAIL**                             | They are distinct records, but only the first is signed. The decision is Ed25519-signed and timestamped; the settlement outcome is an unsigned mutable store row with `preparedAt`/`startedAt`/`resolvedAt`. There is no signed post-settlement artefact anywhere in the repository.                                                                                                                                                  |
| R5  | Canonicalisation — does key reordering, unicode normalisation, or numeric representation change the digest of a semantically identical receipt? | No                                                                                                       | **PASS**                             | RFC 8785 JCS via `canonicalise` (`canonical.ts:6`), exercised by the pre-existing `test/unit/canonical.test.ts` and relied on throughout this suite: `D2` measures reach by hash-diffing 22 fields and every semantically identical rebuild hashed identically. Amounts use a canonical decimal form with a uniqueness refinement (`schemas.ts:19`).                                                                                  |
| R6  | Can the adapter be induced to sign attacker-controlled fields verbatim into a receipt without labelling their provenance?                       | No                                                                                                       | **FAIL**                             | Yes, it can — this is F-6 and F-7 together. `D2` classifies 14 of 22 policy-, hash- or receipt-reaching fields as validated against nothing, all of them caller-supplied. `D8:F6-no-server-side-derivation` signs an entirely caller-authored action. `inntris-decision-v1` carries no provenance field of any kind, so nothing in the receipt distinguishes a derived fact from a copied one (`D5:F6-path-indistinguishable`).       |
| R7  | Does the Merkle batch and anchor cover failure receipts, and can a receipt be omitted from a batch without detection?                           | Covered; omission detectable                                                                             | **N/A** _(structural)_               | There is no Merkle batching or anchoring in this repository: a case-insensitive search for `merkle` and `anchor` across `packages/`, `apps/` and `scripts/` returns nothing. The README states anchoring is not required for decision validity. Recorded as structurally absent rather than untested — but note that R7's underlying concern, selective omission, is unanswered by any other control here.                            |

**R3 is a positioning risk, not just a bug.** If the adapter emits receipts only on the happy path,
then the receipt corpus is a selected sample, and any customer or auditor who notices this will
discount the whole record. The correct behaviour is to attest to the rejection with the same rigour
as the acceptance.

---

## 5. Findings

_Nine findings. F-1 to F-8 carry the identifiers assigned in the round-2 and round-3 briefs; F-9 is
new from this round's Group E execution. All are **Open** — round 3 was a baseline round and no
product code was changed._

### F-9 — Settlement is accepted on a facilitator's word, with no independent confirmation

- **Severity:** Critical
- **Rules implicated:** SR4; Server-SR1
- **Tests:** `E2:no-transaction-identifier`, `E3:unconfirmed-transaction`, register rows E2, E3, R1
- **Location:** `packages/x402-adapter/src/guard.ts:255-307`
- **Description:** `settleIfAuthorised` invokes a caller-supplied executor and treats **any return
  that does not throw** as a settled payment. It never inspects the returned value. The adapter
  contains no chain client, no RPC configuration and no confirmation-depth setting.
- **Reproduction:** `pnpm test:security`, cases `E2:*` and `E3:*`.
- **Observed:** A facilitator answering `success` with an empty transaction identifier had the
  resource released and the operation marked succeeded. A facilitator answering `success` with a
  plausible but phantom transaction hash produced the same outcome.
- **Expected:** Confirm the transaction against the chain at a stated depth, validating recipient,
  asset and amount, before treating the payment as settled.
- **Impact:** An agent obtains the protected resource without a settled payment whenever the
  facilitator is wrong, buggy or lying, and Inntris signs nothing that would later contradict it.
  The reference study found rule violations in every one of the 15 facilitators it evaluated, and
  documents a case where a facilitator API and the chain disagreed in _both_ directions.
- **Remediation:** Add chain confirmation with a configured depth, or state in every claim that
  Inntris attests to a facilitator's response rather than to a settlement. The second is a
  defensible product; it is not the current positioning.
- **Status:** Open

### F-5 — Cumulative spend limits keyed on a caller-supplied identifier

- **Severity:** Critical
- **Rules implicated:** none of SR1–SR8 directly; this is an Inntris product control
- **Tests:** `D8:F5-principal-tenancy`, `D2:principal-keyed-budget`
- **Location:** `packages/policy-engine/src/local-provider.ts:259` (`spendDayKey`),
  `packages/policy-engine/src/evaluate.ts:135`, `apps/demo-api/src/app.ts:30`
- **Description:** The daily cumulative total is keyed on `principal_id`, which is unvalidated and,
  on the HTTP path, taken from the request body. The bearer credential is a single shared service
  key that is never associated with a tenancy.
- **Reproduction:** `pnpm test:security`, case `D8:F5-principal-tenancy`.
- **Observed:** One credential authored decisions naming `org_demo` and `org_attacker`; each carries
  an independent daily budget.
- **Expected:** Key the limit on an identity bound to the authenticated credential; reject a
  principal supplied in the request.
- **Impact:** Any caller able to vary its principal has **no cumulative daily limit at all**. This
  is the mechanism behind a headline product claim.
- **Remediation:** Bind `principal_id` server-side to the credential. Filed separately from F-1
  deliberately: a tenancy identifier cannot be derived from a signature, so an F-1-style provenance
  fix would leave this bypass intact.
- **Status:** Open

### F-6 — One receipt format, two trust levels, no marking

- **Severity:** Critical (structural)
- **Rules implicated:** SR1; R2, R6
- **Tests:** `D8:F6-no-server-side-derivation`, `D5:F6-path-indistinguishable`
- **Location:** `apps/demo-api/src/app.ts:208-249` versus `packages/x402-adapter/src/guard.ts:67-92`
- **Description:** The library guard derives the action from requirements it holds.
  `POST /v1/decisions/evaluate` accepts a fully pre-built action and re-derives nothing. Both sign
  with the same key and emit the same format.
- **Reproduction:** `pnpm test:security`, cases above.
- **Observed:** A caller-authored action carrying 150000000 atomic units declared at 9 decimals
  produced a signed `ALLOW` reading `0.15`, over a requirements hash the server never recomputed.
  Stripped of per-issuance values, a derived and an asserted decision are field-identical.
- **Expected:** Either re-derive server-side, or mark the receipt's provenance so a verifier can
  tell the two apart.
- **Impact:** Receipts of materially different evidentiary weight are indistinguishable offline.
  Every attestation claim is only as strong as the weakest path that can produce it.
- **Remediation:** See `docs/security/F6_RECEIPT_TRUST_OPTIONS.md`. Recommendation there is Option B
  first (typed non-attesting receipts), Option A (server-side re-derivation) as the target, gated on
  F-1's asset registry.
- **Status:** Open — decision required before schema work

### F-1 — Caller-declared `assetDecimals` rescales the amount policy evaluates

- **Severity:** High
- **Rules implicated:** SR1
- **Tests:** `A3-F1`, `D5:assetDecimals`, `D4:property-limit`
- **Location:** `packages/x402-adapter/src/binding.ts:50-69`, `binding.ts:92`; exposed at
  `apps/demo-api/src/app.ts:59`
- **Description:** The atomic-to-decimal conversion uses a caller-supplied precision that is not
  derived from the asset and is not recorded in the receipt.
- **Reproduction:** `pnpm test:security`, case `A3-F1`.
- **Observed:** Atomic `150000000` is `BLOCK`ed as `150.00` at `assetDecimals=6` and `ALLOW`ed as
  `0.15` at `assetDecimals=9`. Action hash, decision and requirements hash are mutually consistent
  in both cases; settlement proceeds and the resource is released.
- **Expected:** Derive precision from the asset via a registry; reject unknown `(network, asset)`
  pairs.
- **Impact:** Every per-transaction, daily and human-approval threshold is bypassable by declaring a
  larger precision. Undetectable to an offline verifier (`D5:assetDecimals`).
- **Remediation:** Asset registry keyed on `(network, asset)`; remove `asset_decimals` from
  externally reachable request schemas; carry atomic amount and declared precision into the signed
  action so the conversion is recomputable.
- **Status:** Open

### F-2 — Default configuration re-settles an identical retry and loses outcome bookkeeping

- **Severity:** High
- **Rules implicated:** SR5 (idempotency); Server-SR1, Server-SR2
- **Tests:** `A6-F2`, `A7-late-nostore`, `D6:replay-same-ref:default-no-reconciliation-store-`
- **Location:** `packages/x402-adapter/src/guard.ts:214-216`
- **Description:** `reconciliationStore` is optional. Without it, an `idempotent` nonce consumption
  is treated as success and the executor is called again; and a settlement failure propagates as the
  raw executor error.
- **Reproduction:** `pnpm test:security`, cases above.
- **Observed:** Two settlement calls and two resource releases for one authorisation. On failure: no
  `InntrisGuardError`, no reason code, no unresolved record.
- **Expected:** Never invoke the executor twice for one authorisation; always produce an
  attributable refusal.
- **Impact:** Double payment and lost reconciliation state in the configuration a deployment gets by
  default. D6 confirms this is the only configuration that flips a core-matrix answer.
- **Remediation:** Require a store for `settleIfAuthorised`, or refuse to settle on an `idempotent`
  consumption without one and raise `RECONCILIATION_REQUIRED`.
- **Status:** Open

### F-7 — Receipt asserts protocol facts that were never evaluated

- **Severity:** High
- **Rules implicated:** SR1, SR3; R6
- **Tests:** `D2:unevaluated-fields-in-receipt`, `D2:agent-id-unevaluated`,
  `D5:F7-unevaluated-not-detectable`, `D7:scheme-allowlist`
- **Location:** `packages/policy-engine/src/evaluate.ts:149-232` (which fields are read),
  `packages/x402-adapter/src/binding.ts:85-107` (which are bound)
- **Description:** `scheme`, `agent_id`, `maxTimeoutSeconds`, `validBefore` and the payload's own
  `resource.url` are bound into the receipt or its hashes and evaluated by no rule.
- **Reproduction:** `pnpm test:security`, cases above.
- **Observed:** A signed `ALLOW` carrying `scheme: "deferred"`, `agent_id: "agent_impostor"`,
  `maxTimeoutSeconds: 86400` and an authorisation whose `validBefore` is in the past verifies
  cleanly. Its reason codes name no field.
- **Expected:** Evaluate the field, or label it as unevaluated.
- **Impact:** An offline verifier over-reads the receipt. A receipt naming an agent does not mean
  that agent was authorised; a receipt naming a scheme does not mean that scheme was approved as
  such.
- **Remediation:** Per-field provenance labelling (shares a mechanism with F-6), plus a `scheme`
  allowlist.
- **Status:** Open

### F-3 — Verify-before-settle is convention, not structure

- **Severity:** Medium
- **Rules implicated:** SR2, SR5, Server-SR1
- **Tests:** `A7-A8-F3`
- **Location:** `packages/x402-adapter/src/guard.ts:150-160`
- **Description:** `settleIfAuthorised` takes an opaque executor and has no facilitator seam or
  notion of a verification result.
- **Reproduction:** `pnpm test:security`, case `A7-A8-F3`.
- **Observed:** Settlement completed with the facilitator's `verify` never invoked, against a
  facilitator that would have rejected the payment.
- **Expected:** Make the safe order the easy one.
- **Impact:** The adapter's defence against F-4, F-9, insufficient balance and forged signatures is
  entirely the facilitator's verification step, and nothing structurally guarantees it is called.
  The primary README sequence diagram goes consume → settle and depicts no verify call, so an
  integrator following the main documentation builds the unsafe order.
- **Remediation:** A `settleVerified` entry point taking a facilitator client; at minimum, correct
  the sequence diagram.
- **Status:** Open

### F-4 — The inner signed authorisation is hash-bound but never cross-checked

- **Severity:** Medium (compensating control exists, but see F-3 and F-9)
- **Rules implicated:** SR1, SR2
- **Tests:** `A10-F4`, register row A1
- **Location:** `packages/x402-adapter/src/binding.ts:71-107`
- **Description:** Every policy field derives from `accepted`; `payload` is bound only as an opaque
  hash. Nothing compares `authorization.to` with `accepted.payTo`, `authorization.value` with
  `accepted.amount`, or `validBefore` with the decision's expiry.
- **Reproduction:** `pnpm test:security`, case `A10-F4`.
- **Observed:** A payload paying `0x…ff` a value of `1` produced a valid `ALLOW` for payee `0x…01`
  and amount `4.50`; `verifyBeforeSettlement` returned valid. Under the permissive stand-in the
  resource was released.
- **Expected:** Scheme-aware cross-checks for `exact` before the action is built.
- **Impact:** An Inntris `ALLOW` attests to what was _quoted_, not to what was _signed_.
- **Remediation:** Assert `authorization.to == accepted.payTo` and
  `authorization.value == accepted.amount`; fail closed on an `exact`-scheme payload that does not
  parse.
- **Status:** Open

### F-8 — Binding checks run after the facilitator has already seen the payload

- **Severity:** Medium
- **Rules implicated:** SR1; ordering
- **Tests:** `A1b`, `A3b`, `D6:F8-facilitator-unreachable`
- **Location:** ordering property of the documented integration;
  `packages/x402-adapter/src/guard.ts:156`
- **Description:** In the documented order every Inntris binding check is `POST_VERIFY`. D1 measured
  it: under a compliant facilitator, payee and amount swaps are rejected at `FACILITATOR_VERIFY`
  before Inntris is consulted.
- **Reproduction:** `pnpm test:security`, cases above.
- **Observed:** Three consequences. The payment payload reaches a third party before Inntris has
  judged it well-formed. A facilitator call is spent on every request that was always going to be
  rejected — cost, rate limit and an amplification path. And when the facilitator is unreachable, a
  request Inntris could have rejected on its own fails as a transport exception with no verdict and
  no reason code (`D6:F8-facilitator-unreachable`) — it fails closed, but unattributably.
- **Expected:** Reject a malformed or unbound request before any facilitator call.
- **Impact:** Availability of a third party determines whether a refusal is attributable, and
  requests that will certainly be refused still leave the trust boundary.
- **Remediation:** Move the binding re-check ahead of the facilitator call in the documented order
  and in any `settleVerified` seam built for F-3.
- **Status:** Open

---

## 6. Claims register

The purpose of this section is to stop the review from being over-read. Each claim is unlocked only
by specific passing tests with attached evidence. A claim whose gate is not met **is not to appear**
in the README, the deck, investor correspondence, or partner materials.

| Claim                                                                                                 | Gate                | Unlocked                                                                                                                                                                          |
| ----------------------------------------------------------------------------------------------------- | ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| "The adapter withholds the resource until settlement is confirmed."                                   | E1, E3, E5 all PASS | **NO.** E3 FAIL. E1 and E5 pass only with a reconciliation store configured.                                                                                                      |
| "Payment requirements are cryptographically bound to the signed authorisation."                       | A1–A5, A10 all PASS | **NO.** A1 FAIL, A5 FAIL. A2/A3/A4/A10 pass, so the _declared requirement fields_ are bound to the decision — but not to the signed authorisation, which is what this claim says. |
| "Replay and concurrent reuse of an authorisation are prevented at the resource boundary."             | C3, C4, E5 all PASS | **NO.** C4 NOT TESTED — and it is the case the reference paper actually exploited. C3/E5 pass only with a reconciliation store.                                                   |
| "Inntris receipts attest to confirmed on-chain settlement, not to a facilitator's response."          | E3, R1 both PASS    | **NO.** Both FAIL. The receipt attests to neither: it is issued before settlement and never amended, and settlement is accepted on the facilitator's word (F-9).                  |
| "Inntris records rejected and failed payments with the same integrity guarantees as successful ones." | R3, R7 both PASS    | **NO.** R3 FAIL for settlement failures (signed only for policy rejections); R7 N/A — no batching or anchoring exists.                                                            |

**Every gated claim is locked. None may appear in the README, the deck, investor correspondence or
partner materials.**

### Claims the evidence does support

Stated in the narrowest form the results actually carry. Each is conditional on the library
integration path with a reconciliation store configured — say so when using them.

- "Against a facilitator that approves everything, the adapter still refuses recipient, asset,
  amount and network substitution, expired decisions, and reuse of a spent authorisation." — D1
  permissive-run evidence, 14 of 22 cases Inntris-owned.
- "A decision is bound to the exact payment requirements it was issued against; any change to those
  requirements is refused before settlement." — A2, A3, A4, A8, A10.
- "An authorisation is single-use: one decision yields at most one settled execution." — A6, A9, E5,
  with the F-2 configuration condition stated.
- "When a settlement attempt fails or times out, the resource is withheld, no automatic retry
  occurs, and the operation is recorded for reconciliation." — E1, E4, with the F-2 configuration
  condition stated.
- "Decision verification is fully offline and requires no Inntris account, API, database or
  blockchain node." — R5, and the whole suite, which verifies signatures locally throughout.

### Claims that are newly unavailable as a result of this round

- ❌ _"Inntris enforces spend limits."_ F-1 and F-5 each defeat them independently.
- ❌ _"Inntris prevents double-spend."_ True only with a reconciliation store; false by default
  (F-2).
- ❌ _"Inntris validates the payment."_ It validates the quoted requirements. Signature, balance and
  settlement are all the facilitator's (SR2, SR4, SR5 all `ABSENT`).
- ❌ Any use of the word **"attests"** about settlement, on any path. See F-9 and R1.
- ❌ Any claim that does not name the integration path, given F-6.

**Claims that are not available regardless of results:**

- ❌ _"Inntris is compliant with the eight USENIX x402 security rules."_ Category error — those
  rules govern facilitators. Correct form: _"The adapter enforces the two server-side acceptance
  rules derived in the USENIX Security '26 analysis, and independently re-derives the
  facilitator-side binding, authenticity and settlement checks rather than relying on the
  facilitator's verdict."_
- ❌ _"Inntris is secure against the attacks in the paper."_ The paper's own framing is that passing
  implemented checks is not a general security claim. Use: _"Tested against N attack cases derived
  from the USENIX Security '26 rule set; results and evidence below."_
- ❌ Any claim about a **named facilitator's** compliance or non-compliance. The paper anonymised
  its per-facilitator results deliberately. Naming a third party's weaknesses from your own testing
  is a disclosure action with legal and commercial consequences, not a marketing line.
- ❌ Any comparative claim of the form "unlike X, Inntris…" unless X's behaviour was tested under
  authorisation and the result is attached.

---

## 7. Reproduction

- **Repository and commit:** `inntris/inntris-x402-policy-adapter`, branch
  `claude/internet-access-question-jgdrey`. **Baseline commit: `__BASELINE_SHA__`.** The evidence
  bundle was generated at that commit; this document, which records the digest, is the commit that
  follows it.
- **Network(s) and chain ids:** none. No network was contacted and no chain was read. The
  requirements under test name `eip155:8453` and `eip155:84532` as data only.
- **Facilitator(s) exercised, and authorisation basis for testing each:** none. Both facilitators
  are local deterministic stand-ins defined in `test/security/harness.ts` — `compliantFacilitator()`
  enforces the `exact` scheme's recipient and value rules, `permissiveFacilitator()` approves
  everything. **No adversarial payload was sent to any third-party facilitator, and no third-party
  facilitator is named in this document.**
- **Test wallets:** none. All addresses are non-custodial constants (`0x…0001` payee, `0x…0002`
  payer, `0x…00ff` attacker). No key material of any kind was used beyond the repository's
  deliberately public fixture signing identity.
- **Harness entry point and command:**
  ```bash
  nvm use 24                      # engines require Node >= 24.18.0 < 25
  pnpm install --frozen-lockfile
  pnpm test:security              # 65 tests across 8 files; regenerates the evidence bundle
  pnpm test:unit                  # 168 pre-existing tests, unchanged by this review
  ```
- **Raw evidence location:** `evidence/x402-security-review.json` (86 cases), with its SHA-256 in
  `evidence/x402-security-review.json.sha256` and per-file shards under `evidence/security/shards/`.
  Supporting analyses: `docs/security/D3_RULE_TO_CODE_MAP.md`,
  `docs/security/F6_RECEIPT_TRUST_OPTIONS.md`, `docs/security/USENIX_X402_SECURITY_RULES.md`.
- **Evidence bundle digest (SHA-256):** `__BASELINE_DIGEST__`
- **Corpus seed:** `20260817`, fixed in `test/security/global-setup.ts`. The D4 mutation corpus is
  regenerated identically on every run.
- **Runtime:** Node.js 24.19.0, pnpm 10.18.1, vitest 4.1.10, Linux x64.

---

## 8. Limitations

1. Results establish behaviour against the implemented checks only. They are not a general security
   claim, and this review does not assert one.
2. No facilitator was tested. Both stand-ins are local and deterministic, so nothing here
   characterises any real facilitator's behaviour, and no comparative claim is available.
3. Chain reorganisation is out of scope in the strongest sense: the adapter performs no chain read
   at any depth, so there is no configured depth to state (F-9).
4. Contract-wallet signature models are neither parsed nor rejected — they pass through unexamined
   (B4, B5). "Unsupported" would be an inaccurate description.
5. **No live settlement was performed.** No on-chain transaction, no funded wallet, no real
   `/settle` call. The pre-existing `pnpm test:x402-sandbox` probe covers live facilitator
   connectivity and `/verify` rejection only, and is not part of this review's evidence.
6. **In-memory stores only.** The PostgreSQL implementations — including the atomic policy state
   store whose concurrency properties matter for C4 — were not exercised.
7. **All cases are sequential.** No concurrency was tested. C4, the reference paper's validated
   free-shopping exploit, is the most consequential gap in this baseline.
8. **The KYA OS authority layer, and the AP2, A2A, EVM, card and MCP rails, were not assessed.** F-1
   and F-5 reach the KYA x402 endpoint because it accepts `asset_decimals` and a
   presentation-derived principal, but KYA's delegation, proof and revocation logic is untested
   here.
9. No cryptographic review of Ed25519 signing or RFC 8785 canonicalisation was performed; both are
   exercised by the pre-existing unit suite but neither was independently audited.
10. Transport-level concerns beyond D8's authentication and rate-limit inventory — TLS, header
    handling, request smuggling — were not assessed.
11. Excluded protocol surface is enumerated with reasons in evidence case `D7:untested-surface`; it
    is not summarised here so that the two cannot drift apart.
12. The D4 property (_a policy-bearing mutation changes the decision or is rejected_) returned zero
    silent mutations across 47 cases. That result must be read with `D4:property-limit` attached:
    F-1 satisfies the property while remaining a complete bypass, because it changes the decision to
    a false but internally consistent figure.

---

## 9. Publication gates

Before any part of this document, or any claim derived from it, leaves internal use:

- [ ] Repository CI/GitHub Action audit completed _(standing precondition for published security
      commentary)_
- [ ] No partner, pipeline, or prospect names appear anywhere in the document
- [ ] Every third-party facilitator named has either been removed or has an authorisation record and
      a completed disclosure process
- [ ] Every claim in §6 traced to a passing test with attached evidence
- [ ] Every `N/A` justified by a structural fact, not a roadmap item
- [ ] Counsel review if any finding concerns a third party's system
