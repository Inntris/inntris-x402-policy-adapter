# Independent Pulse AP2 x402 v0.3 evaluator

This private workspace package evaluates the frozen Pulse AP2 x402 v0.3 corpus offline. It is
isolated from Inntris production policy, database, settlement and AP2 bridge paths.

The implementation uses the existing Inntris JCS canonical byte primitive, the separately pinned
official AP2 SDK boundary, general purpose cryptographic libraries, and independently authored
checks. It does not import or call Pulse verifier code, compiled output, AP2 crypto code,
canonicalisation code, generators, fixtures or tests.

## Frozen inputs

| Item                      | Value                                                              |
| ------------------------- | ------------------------------------------------------------------ |
| Fixture commit            | `e06a6cbfe3ddb965c8fc70f50838f5014ec2038e`                         |
| Fixture path              | `fixtures/v0.3/cases.json`                                         |
| Raw SHA 256               | `8f40be1bdc3d4458f758100e91b418b6a335c5d8d358723f118e2d3e1ad84ee0` |
| Evidence validator commit | `fe24b304735c8ab1f38118a89d0a204bc7d00fe8`                         |
| Required cases            | 80 unique identifiers, exactly once                                |
| AP2 SDK commit            | `e1ea56db72a6385bce3e5c1112b3a56ce60acb43`                         |
| x402 packages             | `@x402/core@2.23.0`, `@x402/evm@2.23.0`                            |

## Install and test

Use Node.js 24.18.0, pnpm 10.18.1 and Python 3.12.

```bash
pnpm install --frozen-lockfile
python -m pip install "git+https://github.com/google-agentic-commerce/AP2.git@e1ea56db72a6385bce3e5c1112b3a56ce60acb43"
python -m pip install --upgrade -r packages/ap2-runtime-gate/python/security-overrides.txt
pnpm test:pulse
```

## Blind and evaluate

Download the exact raw fixture without opening or transforming it. The blinding command verifies its
raw bytes against the pinned SHA 256, removes every top level case `expected` member, validates the
blinded bundle, and refuses to overwrite an existing output.

```bash
pnpm pulse:blind -- \
  --source frozen-cases.json \
  --output evaluator-input.json

pnpm pulse:evaluate -- \
  --input evaluator-input.json \
  --record reproduction.json \
  --implementation-commit <full-lowercase-implementation-commit> \
  --organization Inntris \
  --published-url <stable-https-record-url> \
  --command "pnpm pulse:evaluate -- --input evaluator-input.json --record reproduction.json"
```

The evaluator rejects input containing a key named `expected` at any depth. Case identifiers and
descriptions are carried into results only and never control evaluation.

Do not obtain or run the Pulse evidence validator until the implementation commit and the first 80
result record have both been frozen. The manual `Independent Pulse AP2 x402 v0.3` workflow enforces
that sequence and preserves the record plus its SHA 256 as an immutable workflow artefact.

Passing the offline evaluator or the separately pinned evidence validator does not prove publisher
identity, independence, live settlement, chain finality, production readiness or qualification.
