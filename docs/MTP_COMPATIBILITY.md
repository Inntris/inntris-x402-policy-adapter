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
principal, transaction and x402 protocol references.

This repository does not redefine an old MTP signing version. It introduces an explicitly named
`inntris-action-v1` contract for portable decisions.

## Evidence-pack boundary

An `inntris-decision-v1` object is not an existing evidence-pack manifest, receipt or Merkle leaf.
The public evidence-pack verifier must not be claimed to verify this decision until MTP deliberately
emits the decision as a signed pack artifact and the public verifier adds that versioned check.

Future integration should:

1. Keep existing evidence-pack v1 history verifiable.
2. Add a decision artifact through an explicit pack-format revision.
3. Publish producer schema, verifier logic, methodology and checksums together.
4. Keep request hash, decision hash and execution hash distinct.

## Key separation

The decision-service signer must not reuse:

1. The offline evidence-pack seed.
2. An agent request-signing key.
3. A blockchain anchor-worker wallet key.

The fixture identity in this repository is intentionally public and has no production authority.
