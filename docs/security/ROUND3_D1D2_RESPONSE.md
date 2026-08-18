# Claude Code Brief — Round 3, D1/D2 Response

D1 and D2 are accepted. Two method choices were right and stay: deriving reach empirically by
mutation-and-diff rather than reading schemas, and introducing `INNTRIS_CONTAINMENT` as a distinct
owner. Both improve on the brief.

Three findings below are new or re-rated. Two blockers are resolved.

---

## Blockers resolved

**Rule list.** `USENIX_X402_SECURITY_RULES.md` accompanies this brief — commit it to the repository.
It carries SR1–SR8 and Server-SR1/SR2 with dispositions and the required D3 mapping columns. Note
that the mapping table there is wider than the brief specified: D1 and D2 established that **path**
and **ordering** are load-bearing, so both are now columns.

**Review document.** `INNTRIS_X402_SECURITY_REVIEW.md` accompanies this brief and uses the
§1.2/§1.3/§2/§6/§7/§8/§9 numbering the freeze protocol references. Commit it as-is; do not renumber
anything. Merge the round-1 document's content into its sections and delete the round-1 file. Where
round 1 recorded something the template has no home for, add a section rather than reshaping the
existing ones.

---

## New findings

### F-5 (Critical) — cumulative spend limits keyed on a caller-supplied identifier

`spendDayKey` derives from `principalId`, and `principalId` is unvalidated. Each distinct value
carries an independent daily total, empirically confirmed with `org_demo` and `org_other`.

**Filed separately from F-1 deliberately.** F-1's remediation is "derive the fact from the signed
authorisation." `principalId` is a tenancy identifier and cannot be derived from a signature. Its
fix is different in kind: bind it server-side to the authenticated credential and reject any value
supplied in the request. Folding this into F-1 will produce a provenance fix that leaves the bypass
intact.

**Impact is total, not partial.** Any caller able to vary its principal has no cumulative daily
limit at all. This is the mechanism behind a headline product claim.

**Do not fix yet** — F-5 is frozen with the rest until baseline completes. Record it and add a
regression case: two evaluations under differing `principalId`, same credential, must share one
daily total.

### F-6 (Critical, structural) — one receipt format, two trust levels, no marking

`POST /v1/decisions/evaluate` accepts the entire pre-built action from the request body — amount,
payee, asset, network, resource, purpose, principal, agent, and the payment-requirements hash — and
never re-derives any of it. Derivation happens only in `InntrisX402Guard.authorise`, library-side.

The consequence is not a validation gap. It is that receipts from the two paths carry materially
different evidentiary weight, share a format, are signed by the same key, and are
**indistinguishable to an offline verifier**. On the HTTP path every policy-bearing fact is
client-asserted; the receipt does not say so.

This subsumes part of the F-1 remediation and expands it. The provenance labelling already specified
must additionally record the derivation path, and the design question — whether the HTTP endpoint
should re-derive server-side from raw requirements and payload, or emit explicitly non-attesting
simulation receipts under a distinct type — needs a decision before any schema work starts.

**Deliverable for this round, no code changes:** a one-page options note stating the two designs,
what each costs, and which existing integrations each would break. D8 supplies the exposure input.

### F-7 (High) — receipt asserts protocol facts that were never evaluated

`scheme` is decorative: `scheme: "deferred"` produced a valid signed ALLOW whose
`protocol_reference.scheme` reads `deferred`, with no evaluation of the deferred scheme. `agentId`
reaches the action hash and the receipt but is never read by `evaluatePolicy`, so a receipt naming
an agent does not mean that agent was authorised on the plain x402 path. `maxTimeoutSeconds` and
`authorization.validBefore` reach the receipt without ever being compared to decision expiry.

These are one class: **the receipt states facts Inntris did not check, in a format that implies it
did.** The remediation is the provenance labelling under F-1, plus an allowlist for `scheme`.
Flagging separately because the claims impact differs — this is what an offline verifier over-reads,
rather than what an attacker manipulates.

---

## Re-rating

**A7 insufficient balance — BORROWED is correct, but the permissive-run severity overstates it.** No
real facilitator can settle a payment the payer cannot fund, so the permissive stand-in's
`settle: success` is not a reachable state on its own. The finding still holds, for a chained
reason: Inntris performs no independent settleability check _and_ performs no independent settlement
confirmation (F-3, and E2/E3 still untested). Either one alone is survivable; together they are free
shopping. State A7's severity as conditional on the E3 result and resolve it when E3 runs.

**Binding checks are `INNTRIS_POST_VERIFY`, and should be `INNTRIS_PREFLIGHT`.** D1 shows payee and
amount rejections attributed to `FACILITATOR_VERIFY` under the compliant stand-in. Three
consequences worth recording as a Medium finding (F-8):

- the payment payload reaches a third party before Inntris has judged it well-formed;
- a facilitator call is spent on every request that was always going to be rejected — cost, rate
  limit, and an amplification path;
- the failure mode when the facilitator is slow, erroring or unreachable is untested. **Add that
  case:** facilitator times out or returns 5xx on a request carrying a mutated payee. Does the
  adapter fail open or closed?

Record the ordering per rule in the D3 `Ordering` column.

**`A7-late-nostore` downgrades the strongest round-1 claim.** The clean containment property — one
settlement call, no facilitator re-call on retry, resource never served, operation left unresolved —
holds only when `reconciliationStore` is configured, which is not the default. On the default path a
settlement failure yields a raw executor error with no reason code and no unresolved record. The §6
claims row must carry that condition explicitly.

---

## Remaining round-3 order

Unchanged in substance, with one addition:

1. **D8** — promoted ahead of D5 and D6. It settles exposure for both F-1 and F-5, and it is an
   input to the F-6 options note. Cover authentication, authorisation, rate limiting and
   reachability for `/v1/decisions/evaluate` and every sibling.
2. **D5** — offline detectability. Add rows for the F-7 fields: can a receipt-only verifier tell
   that `scheme`, `agentId`, `maxTimeoutSeconds` and `validBefore` were unevaluated? Add a row for
   the F-6 question: can a verifier tell which path produced the receipt?
3. **D6** — configuration matrix. `reconciliationStore` present/absent is now known to change two
   behaviours, so run the full core matrix under both rather than spot-checking.
4. **D3** — unblocked. Use the wider table.
5. **D4** — mutation corpus. D2's 14 unvalidated fields are the priority targets; the property to
   assert is the F-1 signature generalised.
6. **D7** — protocol surface.
7. Freeze protocol.

**F-6 options note** slots after D8.

---

## Still frozen

No product code changes. F-1, F-2, F-3, F-5, F-6, F-7, F-8 are all recorded and none are fixed in
this round. Test code, harness, instrumentation and documentation only.

The one exception already taken — `it.fails()` conversion — was correct and is complete.
