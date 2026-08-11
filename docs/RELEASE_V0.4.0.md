# v0.4.0 delegated agent authority

## Scope

Release target `v0.4.0` composes KYA OS delegated agent authority above the existing rails. It keeps
`inntris-action-v1`, `inntris-decision-v1` and the five required conformance rails unchanged.

The release adds live request proof verification, signed modern delegation chains, legacy
compatibility, explicit financial joins, signed failure decisions, fresh approval and consumption
checks, PostgreSQL replay and lifecycle state, KYA API routes, schemas and reproducible public test
evidence.

## Pinned compatibility

1. KYA protocol `1.0.0`.
2. `@kya-os/mcp` `1.12.0`.
3. `@digitalbazaar/eddsa-jcs-2022-cryptosuite` `1.0.0`.

The requested cryptosuite version `1.0.1-0` was not published. The available official `1.0.0`
release is pinned instead.

## Claims boundary

The repository demonstrates local cryptographic authority verification and exact binding to an
Inntris policy decision. KYA is not an Inntris rail. No partnership, endorsement, live funded
settlement, production availability, certified custody or KYA conformance claim is made unless a
separate operating artefact proves it.
