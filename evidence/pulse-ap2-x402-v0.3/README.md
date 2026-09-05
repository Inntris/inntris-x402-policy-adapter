# Pulse AP2 x402 v0.3 qualification evidence

This directory preserves the independently generated record and exact official checker result from
the manual read only GitHub Actions run at:

https://github.com/Inntris/inntris-x402-policy-adapter/actions/runs/33969196769

The run completed successfully on 5 September 2026. It generated and froze the Inntris result before
checking out or installing the Pulse validator.

## Immutable pins

Implementation revision: `5a2c65ea10dc3078d3b38971db7373f1f34cac7c`

Pull request final head before the repository rebase merge:
`f8073e0ef6cd24077272fb8c8e9ec1a3c4b87aae`

Pulse fixture revision: `e06a6cbfe3ddb965c8fc70f50838f5014ec2038e`

Fixture path: `fixtures/v0.3/cases.json`

Fixture SHA256: `8f40be1bdc3d4458f758100e91b418b6a335c5d8d358723f118e2d3e1ad84ee0`

Pulse validator revision: `fe24b304735c8ab1f38118a89d0a204bc7d00fe8`

Workflow run: `33969196769`

Workflow job: `101314585675`

GitHub artefact: `9970418758`

## Result

The record uses `pulse-independent-reproduction/0.1`. It contains 80 unique cases exactly once,
comprising 20 accepts and 60 rejects. The blinded evaluator input and the record contain no
`expected` field.

The SHA256 digest of `reproduction.json` is
`857bade1fe50fb1fc4ecd8c8aefbd2b6563fbb0395a1d59ff99afb62bde7f159`.

The official checker returned `valid: true`, `automatedChecksPassed: true`, and an empty errors
list. The exact JSON is preserved in `official-checker-output.json`.

## Diagnostic rerun disclosure

The first frozen independent record was generated at `7122b22b60221a51ed1f8457b5a723b2273b9a9b`. Its
SHA256 digest was `c957add85307f708c434c2fb251c1bc735e657b75f44103a3c48c1503f191a5f`. The pinned
validator reported 14 mismatches across seven semantic families.

The second frozen independent record was generated at `a173118fa3060e4bdb5513cfa88c36c1e0f9ec12`.
Its SHA256 digest was `b2f476692be36757d87ba25049c1dab36cea860566503856d190ae1e2e48231b`. The pinned
validator reported two remaining receipt status mismatches.

The semantic corrections were derived from the frozen field mapping and independently verified
claims. No fixture expected values were inspected or used as an oracle.

## Boundary

This evidence establishes the pinned offline conformance result. It does not establish a production
deployment, a funded settlement, custody controls, performance, or third party endorsement.

The pinned external validator dependency installation reported three advisories in its own
dependency graph, comprising two moderate findings and one high finding. That external notice did
not alter the frozen record or the successful checker result. The Inntris production audit gate
passed independently.
