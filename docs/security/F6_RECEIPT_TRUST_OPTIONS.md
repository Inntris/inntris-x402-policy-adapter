# F-6 options note — one receipt format, two trust levels

**Status:** decision required before any schema work. No code changes proposed in this round.
**Inputs:** D2 (provenance), D8 (exposure).

## The problem in one paragraph

`InntrisX402Guard.authorise` derives the action from x402 payment requirements it holds: it
normalises the requirements, computes `payment_requirements_hash` itself, checks the payload's
`accepted` block against that hash, and converts atomic units to a decimal amount.
`POST /v1/decisions/evaluate` does none of this. It parses the request body into an
`InntrisActionV1` and hands it to `provider.evaluate` unchanged, so amount, payee, asset, network,
resource, purpose, principal, agent and the requirements hash are all caller-authored. Both paths
sign with the same key, emit the same `inntris-decision-v1` format, and produce receipts that are
**indistinguishable to an offline verifier**. D8 confirmed the HTTP path end to end: a
caller-authored action carrying 150000000 atomic units declared at 9 decimals produced a signed
`ALLOW` reading `0.15`, over a requirements hash the server never recomputed.

This is not a validation gap that a stricter schema fixes. The two paths carry materially different
evidentiary weight and the receipt does not say which one it came from.

## Option A — server-side re-derivation

The HTTP endpoint stops accepting a pre-built action. It accepts raw `payment_requirements`,
optional `payment_payload`, `resource`, `purpose` and the authority material, and performs the same
derivation the library guard performs.

**What it costs**

- A new request shape for the evaluate endpoint. The existing one either goes away or becomes a
  second, explicitly non-attesting endpoint (see Option B).
- Asset precision must be resolved server-side, which requires the asset registry that F-1 already
  needs. Option A cannot ship before that registry exists.
- Principal and agent identity must come from the credential rather than the body, which is F-5's
  fix. Option A subsumes it.
- The server must hold or be told the requirements it served. For a merchant-side deployment that is
  natural; for a deployment where the caller _is_ the resource server, the server is being asked to
  re-derive from data only the caller has, which reduces to trusting the caller again unless the
  requirements are registered first.

**What it breaks**

- Every current caller of `POST /v1/decisions/evaluate` that builds its own action. In-repo that is
  `RemoteInntrisDecisionProvider`, which posts `{ action }` and then re-verifies the returned
  decision against its locally built action. That client would need to change shape, though its
  security posture is already the stronger one — it derives locally and verifies the binding on
  return.
- Nothing else in this repository posts to the endpoint: `RemoteInntrisDecisionProvider` is its only
  in-repo client. The multi-rail packages drive the provider directly and are unaffected.
- The endpoint's schema accepts every rail (`ap2`, `evm`, `card`, `mcp` as well as `x402`), and
  re-derivation is x402-specific. Those rails would need their own derivation or an explicit
  exemption, and an exemption reintroduces the same two-trust-level problem on a different rail
  under the same receipt format.

## Option B — typed, explicitly non-attesting receipts

The HTTP endpoint keeps its shape. The decision it returns carries an explicit provenance field
distinguishing a derived decision from one issued over caller-asserted inputs, and the verifier
surfaces that field. A caller-asserted decision is a policy simulation, not an attestation.

**What it costs**

- A schema change to `inntris-decision-v1`, which changes the fingerprint preimage and therefore
  every committed evidence fixture. This is a versioned migration, not an additive field.
- The verifier must fail closed on an unknown provenance value, otherwise an old verifier reads a
  new simulation receipt as an attestation.
- Documentation and positioning work: the product currently describes one receipt. It would describe
  two, and the weaker one is the one the HTTP API returns by default.

**What it breaks**

- Nothing at the wire level for existing callers, if the field is added with a migration. Existing
  receipts remain verifiable under `v1`; new ones are `v2`.
- The claim surface: any material saying "Inntris receipts attest to the payment" must be qualified
  for the HTTP path.

## Interaction with the other findings

- **F-1** requires the asset registry. Option A needs it as a prerequisite; Option B does not, but
  leaves the precision bypass reachable on the HTTP path.
- **F-5** is fixed by Option A as a side effect. Under Option B it needs its own fix, because a
  simulation receipt keyed on a caller-chosen principal still drives a real cumulative limit.
- **F-7** is the same class as Option B's provenance field: `scheme`, `agentId`, `maxTimeoutSeconds`
  and `validBefore` reach the receipt unevaluated. Whatever labelling mechanism is chosen should
  cover per-field provenance, not just per-receipt.

## Recommendation

**Option B first, Option A as the target.** Option B is a smaller, self-contained change that stops
the receipt from over-claiming immediately, and it does not depend on the asset registry. Option A
is the right end state but is gated on F-1's registry and on resolving the multi-rail question, and
shipping it without those turns re-derivation into re-trusting the caller.

Doing neither is not a neutral position: the current behaviour signs both kinds of receipt with one
key and one format, so every attestation claim is only as strong as the weakest path that can
produce it.

## What is not decided here

- Whether the HTTP path should exist at all for x402, versus library-only integration.
- Whether the asset registry is per-deployment configuration or a shipped dataset.
- Whether the multi-rail endpoints follow x402 or keep the pre-built action shape.
