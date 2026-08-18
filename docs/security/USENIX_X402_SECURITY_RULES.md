# USENIX x402 Security Rules — Reference

**Commit this file to the repository.** It is the rule list D3 requires.

**Source:** Wang, Yang, Chen, Ji, Payer. _When HTTP 402 Meets the Blockchain: Risks on Emerging x402
Payments._ USENIX Security '26. arXiv:2607.19545v1 [cs.CR], 21 July 2026.

The rules below are paraphrased for engineering use. Consult the paper for the authoritative
statements; do not treat these summaries as quotations.

---

## Scope — read before mapping

SR1–SR8 govern **facilitators**: the party that receives a payment payload plus declared
requirements, returns a verification verdict, and constructs, signs, sponsors and broadcasts the
settlement transaction.

Server-SR1 and Server-SR2 govern the **resource server**, and are the rules that apply to a
merchant-side adapter as written.

Where the Inntris adapter is not a facilitator, SR1–SR8 are still worth mapping — not as compliance
obligations but as **checks Inntris chooses to re-derive rather than inherit**. D1 established that
the distinction is measurable: a check the facilitator performs is not a check Inntris owns. Use
these dispositions:

- `ENFORCED` — Inntris must reject; failure is a defect.
- `RE-DERIVED` — Inntris reaches its own conclusion independently and records any disagreement with
  the facilitator.
- `N/A` — the adapter is structurally incapable of violating or satisfying the rule. Requires a
  structural justification, never a roadmap note.

---

## Facilitator rules

### SR1 — Requirement binding

Verification must reject any proof whose contents do not match the server-declared payment
requirements. Covers payee, asset, amount, network and chain identity, scheme, and the resource
being paid for. Both the JSON-level fields and the signed EIP-712 domain (`chainId`,
`verifyingContract`) are in scope — a check on one is not a check on the other.

_Inntris disposition:_ `RE-DERIVED`. Inntris declares the requirements, so it can bind against its
own record.

### SR2 — Authorization authenticity

Verification must reject authorisation that is not authentic under the intended signature model. The
recovered signer must match the declared payer. Contract signature models (ERC-1271, ERC-6492) must
not be accepted where the off-chain verdict can diverge from on-chain execution.

_Inntris disposition:_ `RE-DERIVED`. Signature recovery is local and cheap; delegating it is an
unforced dependency.

### SR3 — Temporal validity

Verification must reject authorisations that have expired, and those not yet valid.

_Inntris disposition:_ `RE-DERIVED`.

### SR4 — Settlement truthfulness

Settlement must report success only when the payment has actually settled on chain. An API response
asserting success is not evidence of settlement; a transaction identifier that resolves is not
evidence that the transaction did what was claimed. Confirmation must validate the transaction's
contents — recipient, asset, amount — at a stated confirmation depth.

_Inntris disposition:_ `RE-DERIVED`. **This is the rule that determines whether Inntris confirms or
relays.**

### SR5 — Fail fast, idempotency, freshness bound

Verification must reject proofs that cannot settle (insufficient balance) or are economically
meaningless (zero amount, dust below fee cost). Nonce consumption must be idempotent, and an
idempotent consumption is a replay signal rather than a success signal. A minimum remaining-validity
window must be enforced, since verification and execution do not happen at the same instant.

_Inntris disposition:_ idempotency `ENFORCED`; settleability and freshness bound `RE-DERIVED`.

### SR6 — Bounded sponsored execution

Where the facilitator sponsors fees or gas, the exposure must be bounded by configurable caps.

_Inntris disposition:_ `N/A` unless Phase 0 established that Inntris sponsors. State the structural
reason.

### SR7 — Re-verification before submission

Conditions must be re-checked immediately before the settlement transaction is submitted, not only
at initial verification.

_Inntris disposition:_ `N/A` as written. The adapter's analogue is re-checking freshness and
validity before releasing the resource. Map that analogue explicitly.

### SR8 — Explicit, unambiguous execution semantics

Only proofs whose on-chain execution semantics are explicitly permitted may be settled. Unexpected
instructions, extra signers, alternative token programs, or deployment payloads must be rejected
rather than executed.

_Inntris disposition:_ `N/A` unless Phase 0 established that Inntris constructs transactions.

---

## Resource server rules

### Server-SR1 — Release only after settlement

The protected resource may be released only after settlement has succeeded under the server's
acceptance criteria. One authorisation yields one release.

_Inntris disposition:_ `ENFORCED`. Primary obligation.

### Server-SR2 — Roll back on settlement failure

Where verification succeeds and settlement subsequently fails, all post-verification effects must be
reversed and the request treated as unpaid.

_Inntris disposition:_ `ENFORCED`. Primary obligation.

---

## How to complete the D3 mapping

One row per rule:

| Column         | Notes                                                                                                                                            |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| Rule           | SR1–SR8, Server-SR1, Server-SR2                                                                                                                  |
| Disposition    | `ENFORCED` / `RE-DERIVED` / `N/A` + justification                                                                                                |
| Implementation | exact `file:line`, or `ABSENT`                                                                                                                   |
| **Path**       | which integration paths it covers — library guard, HTTP evaluate, both. D2 showed these differ; a rule enforced on one path only is not enforced |
| Ordering       | `PREFLIGHT` (before any facilitator call) or `POST_VERIFY`. D1 showed several are post-verify                                                    |
| Nature         | `STRUCTURAL` (a caller cannot bypass it) or `CONVENTIONAL` (correct only if the documented call order is followed)                               |
| Owner          | from D1 attribution: `INNTRIS` / `INNTRIS_CONTAINMENT` / `FACILITATOR` / `NONE`                                                                  |
| Tests          | case IDs exercising it                                                                                                                           |

A rule with passing tests but no identifiable implementation, or with owner `FACILITATOR`, is not
enforced by Inntris regardless of the end-to-end result. Record it that way.
