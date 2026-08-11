# KYA OS authority for Inntris

This package verifies delegated KYA OS authority before an action enters the ordinary Inntris
organisational policy engine. KYA is an authority input, not an Inntris payment rail.

## Pinned upstreams

1. `@kya-os/mcp` `1.12.0` for request proofs, DID helpers, delegation validation, revocation and
   legacy credential verification.
2. `@digitalbazaar/eddsa-jcs-2022-cryptosuite` `1.0.0` for every modern delegation hop.
3. `@digitalbazaar/ed25519-multikey` `1.3.0` and `base58-universal` `2.0.0` for official cryptosuite
   key and signature encoding.

The build specification requested Digital Bazaar version `1.0.1-0`, but that version is not
published in the official npm registry. This repository pins the available official release `1.0.0`
and records the difference rather than inventing a package version.

## Profiles

`entity-card-v1` is the primary profile. It verifies the live request proof, every signed VC 2.0 and
ZCAP delegation hop, structural attenuation, validity, revocation, identity continuity and exact
financial joins.

`legacy-v1` is isolated compatibility. It uses the upstream legacy DelegationCredential and VC JWT
verifier. Financial use additionally requires a live request proof and signed constraints for the
exact audience, `payments.transfer` scope, invocation target, canonical `maxAmount` and currency. It
never receives fallback traffic from a failed modern presentation.

Entity Card `principal` is not trusted as a bare card field. A deployment selecting `card_principal`
must inject `UpstreamEntityCardPrincipalVerifier` with a trusted identity attestation verifier. The
reference API rejects that policy feature unless such a verifier is configured.

## Production requirements

Required mode needs a production safe DID resolver, atomic nonce storage and durable decision and
revalidation state. The reference service uses PostgreSQL for both stores. In memory stores are for
tests and optional development only.

An injected financial request mapper is part of the trusted computing base. The default mapper
accepts only the strict `tools/call` and `payments.transfer` schema.
