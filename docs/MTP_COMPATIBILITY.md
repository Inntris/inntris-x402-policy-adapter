# Compatibility with existing Inntris MTP evidence

## Preserved primitives

This repository preserves the established cryptographic primitives:

1. RFC 8785 JSON Canonicalisation Scheme.
2. SHA 256 hashing.
3. Ed25519 signatures.
4. Explicit public-key fingerprints.
5. Exact executor-side consumption before a side effect.

## Deliberate version boundary

The existing MTP request action hash and `inntris-action-v1` serve different purposes.

The MTP request hash authenticates an agent request envelope containing agent, action type, payload
hash, nonce and timestamp. The new action hash binds the complete policy subject, including
principal, transaction and the versioned rail-specific protocol reference.

This repository does not redefine an old MTP signing version. It introduces an explicitly named
`inntris-action-v1` contract for portable decisions.

## Runtime composition

`@inntris/mtp-authority` now composes the formats at runtime without merging them. For every local
automatic `ALLOW`, it creates an MTP `sig_version: 3` request that embeds the strict action, action
hash, signed decision identity and policy identity. MTP authenticates that request with a dedicated
registered agent key and returns its existing approval token.

The public Decision Envelope remains the exact x402 policy proof. The MTP token remains MTP
execution authority. Both are consumed with one stable execution reference before settlement. Their
hashes, signatures and receipts remain distinct and independently attributable.

The bridge is durable in PostgreSQL. If an MTP response is lost, the same request and execution
reference recover the original receipt. If the process stops after MTP consumption, a retry resumes
local decision consumption without requesting another MTP authority.

## Evidence-pack boundary

An `inntris-decision-v1` object is not an existing evidence-pack manifest, receipt or Merkle leaf.
The public evidence-pack verifier must not be claimed to verify this decision until MTP deliberately
emits the decision as a signed pack artifact and the public verifier adds that versioned check.

Evidence-pack integration should still:

1. Keep existing evidence-pack v1 history verifiable.
2. Add a decision artifact through an explicit pack-format revision.
3. Publish producer schema, verifier logic, methodology and checksums together.
4. Keep request hash, decision hash and execution hash distinct.

## Key separation

The decision-service signer must not reuse:

1. The offline evidence-pack seed.
2. An agent request-signing key.
3. A blockchain anchor-worker wallet key.
4. The registered MTP agent request-signing key.

The fixture identity in this repository is intentionally public and has no production authority.
