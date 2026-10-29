# SAFR PR00 Core to x402 contract evidence

Companion Core PR: https://github.com/KingsmanRon/MTP/pull/142. producer-pin.json pins the exact
PR00 producer commit, whose production serializer is unchanged from
7d493faf1e5cbdad9048298b0eafcac37a94190e.

The x402 base is main at 4312e601e41718e1e0fd1acadfbf48c6769bb89d. The baseline manifest in the Core
PR records all five repository families, their golden vectors and the authority branch relationship.

## Defect and version boundaries

The existing Core HTTP response uses lowercase allow, block and require_approval. Its fixture
catalogue version is inntris-core-authority-http-observed-v1; this is a test identifier, not a new
API field.

The separate signed InntrisDecisionV1 contract uses ALLOW, BLOCK and REQUIRE_APPROVAL. Those
semantics must not be conflated.

The unfinished MtpExecutionClient requires uppercase ALLOW from /authority/evaluate. It is not part
of pinned x402 main. Its original local source is captured unchanged except CRLF normalisation at
packages/mtp-authority/test/fixtures/execution-client.snapshot.ts. snapshot-provenance.json records
both original and normalised SHA256, original source path, local branch and its older inspected Core
commit. The snapshot is outside src and is never exported by the package.

No consumer or producer runtime parser is fixed in PR00. No permissive fallback or production
uppercase conversion is introduced. The synthetic uppercase control exists only to isolate the
defective field.

## Reproduction

Use Node 24.18.0 and pnpm 10.18.1 with the frozen lockfile:

    pnpm install --frozen-lockfile
    pnpm exec vitest run --config vitest.safr-pr00.config.ts --configLoader runner --no-cache test/contracts/safr-pr00/baseline.test.ts
    pnpm exec vitest run --config vitest.safr-pr00.config.ts --configLoader runner --no-cache test/contracts/safr-pr00/compatibility.test.ts

The first command executes ten assertions and succeeds when it reproduces the known rejection,
preserves non executable decisions and rejects unknown values. The second command fails on the
actual lowercase approval. It has no xfail, skip or continue-on-error. The dedicated compatibility
job must remain red until a separately authorised implementation resolves the contract.

CI checks out the immutable Core PR00 producer, verifies its source fingerprints, sends a request
through the real registered HTTP serializer and feeds the generated JSON into this client.
Authentication, service results and database reads are synthetic. The executable action hash is
computed by the existing Core adapter and independently matched by the x402 client. This is wire
compatibility evidence, not live policy, executor authentication, single use persistence or
settlement proof.

Local runs use the committed semantic fixture by default. Set SAFR_CORE_WIRE_FIXTURE to the
producer's freshly exported JSON to reproduce the CI path. The baseline check rejects unexpected
fixture catalogue versions. The existing consumer rejects denial and require_approval.

## Local results and remaining gates

On the verified x402 base, the build and scoped ESLint checks passed. The ten contract baseline
cases and 28 selected existing unit cases passed. Core still emits allow before and after PR00; this
client still rejects it. There is no claim that the defect has been fixed.

The Core companion records 20 pure tests now executing, 146 PostgreSQL dependent cases still gated
and seven privileged DSN cases. No shared database, production secret, live provider or real
transaction is used.

No production source, package export, dependency lock, scanner exclusion or golden vector is
changed. The development snapshot must not be treated as released functionality. PR01, production
qualification and deployment remain unauthorised.
