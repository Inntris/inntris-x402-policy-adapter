# Independent adversarial remediation

This record concerns the isolated evaluator, not Inntris production policy or settlement. The
reviewed frozen implementation was `5a2c65ea10dc3078d3b38971db7373f1f34cac7c`. The remediated
implementation is `b4205e74586113a0ada2b38cf4f27eae8f20a21e`. Subsequent evidence commits do not
change evaluator logic.

The original qualification evidence remains unchanged in `../pulse-ap2-x402-v0.3`. No Pulse
verifier, canonical implementation, crypto implementation, fixture generator or tests were inspected
or used for this remediation. No fixture expected values were used. No external Pulse validator was
run. This replay is not a new external qualification claim.

## Trust model and acceptance invariant

Controlling sources are the frozen
[field mapping](https://github.com/shibutatsu/pulse-ap2-x402-conformance/blob/e06a6cbfe3ddb965c8fc70f50838f5014ec2038e/docs/field-mapping.md),
[guarantee boundary](https://github.com/shibutatsu/pulse-ap2-x402-conformance/blob/e06a6cbfe3ddb965c8fc70f50838f5014ec2038e/docs/guarantee-boundary.md),
[source pins](https://github.com/shibutatsu/pulse-ap2-x402-conformance/blob/e06a6cbfe3ddb965c8fc70f50838f5014ec2038e/docs/source-pins.md)
and
[independent implementation contract](https://github.com/shibutatsu/pulse-ap2-x402-conformance/blob/9940fdb08bc326d949c0c7148c5e01c656454b99/docs/independent-implementation-guide.md).
Relevant general invariants are
[JWT temporal claims, RFC 7519 section 4.1](https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1),
[SD-JWT verification, RFC 9901 section 7.1](https://www.rfc-editor.org/rfc/rfc9901.html#section-7.1),
and
[JCS input restrictions, RFC 8785 section 3](https://www.rfc-editor.org/rfc/rfc8785.html#section-3).

The supplied root and receipt public keys and the expected audience, nonce, checkout reference and
time are context inputs. The evaluator verifies signatures against those inputs; it cannot
authenticate the provenance or operational legitimacy of the inputs themselves. Signed claims are
extracted by the separately pinned AP2 SDK bridge. Unsigned normalised copies and local canonical
hashes are consistency checks, never replacement authority.

Acceptance requires all five mandatory bridge stages to be explicitly verified, all required claim
shapes to validate, and no controlled failures. The stages are root mandate, closed mandate,
terminal binding, mandate time and receipt. A missing or malformed bridge result fails the bridge
contract. An unexplained skipped stage adds `AP2_CRYPTOGRAPHIC_EVIDENCE_INVALID`. Dependent stages
skipped because of an explicit upstream failure do not fabricate extra failures.

The bridge reports each authenticated expiry as `rootJwt`, `openMandate`, `closedJwt` or
`closedMandate`. `effectiveAuthorityExpiry` is their minimum. The TypeScript boundary checks source
uniqueness, required mandate bounds and consistency of the minimum. EIP validity cannot exceed that
minimum. Optional absent outer expiries contribute nothing; the profile requires both inner mandate
expiries. Receipt expiry affects receipt validity, not payment authority.

JWT expiry is exclusive. Not before and issued at checks permit equality. Present null, boolean,
nonnumeric or nonfinite temporal claims reject. Numeric dates outside the exactly interoperable
integer range reject rather than being rounded across the Python/JavaScript boundary. Fractional
numeric dates within that range are supported. EIP timestamps remain integers, so comparison against
a fractional expiry uses its floor. The evaluator profile still requires zero clock skew. The
bridge's separate zero to 300 second skew interface is tested; skew does not extend the signed EIP
authority cap.

## Root causes and results

All paths below are relative to `packages/pulse-conformance-evaluator` unless stated otherwise. The
complete named regression results appear in [regression-results.json](regression-results.json).

| Class and finding                         | Affected function                                                                                | Root cause and reproduction                                                                                                                                    | Fix                                                                                                                                                                                                                                                                     | Regression and final local status                                                                                                                 |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| P0 default bridge: temporal validity      | `python/verify_ap2_structured.py`, `_check_time_claims`                                          | Signed future nbf, equality at exp and null iat accepted. Missing and null were conflated; nbf absent from checks; expiry used the wrong inequality.           | Explicit presence/type checks for iat, nbf and exp in authenticated wrapper and mandate payloads; equivalent receipt checks.                                                                                                                                            | JWT time and skew groups: reject inactive authority with `AP2_MANDATE_TIME_INVALID`; valid boundaries accept. Pass.                               |
| P0 default bridge: authority expiry       | Same bridge and `src/evaluator.ts`, `evaluateCase`                                               | Outer expiry was discarded; signed payment could outlive root or terminal wrapper.                                                                             | Explicit signed expiry contributors and checked minimum retained across the bridge and enforced against EIP validBefore.                                                                                                                                                | Expiry composition group: root, leaf, differing minima, equality, plus one second, absent optional wrapper bound. Pass.                           |
| P0 default bridge: presentation tampering | `python/presentation.py`, `validate_presentation`                                                | SDK reconstructed reachable claims but silently ignored extra disclosures. Appended bytes could be accepted without authorising the injected content.          | Independently traverse signed digest structure; require every presented disclosure consumed; validate shapes, digest uniqueness, reserved members and nested paths. Signature authority remains with the pinned SDK.                                                    | Disclosure group: orphan, malformed, duplicate, tampered, no resign append and valid chain; supplementary nested object/array Python tests. Pass. |
| P0 parser: ambiguous JSON/JCS             | `src/strict-json.ts`, `parseStrictJson`, `assertJsonValue`; input, hashing and schema callers    | JSON.parse erased duplicate names before inspection; lone surrogates reached canonical hashing.                                                                | Parse member names before constructing objects; reject duplicates, invalid Unicode and nonfinite numbers. Guard object APIs and hashing as well as raw input. Validate encoded JWT/disclosure JSON separately in Python. Shared production canonicalBytes is unchanged. | Raw JSON/JCS group: concealed expected, conflicting success, nested/escaped duplicates, both surrogate halves, ordinary Unicode. Pass.            |
| P1 interface architecture: skipped stages | `src/ap2-bridge.ts`, `parseStructuredVerification`, `allMandatoryStagesVerified`; `evaluateCase` | All notEvaluated, or an individually skipped stage, could accept. A missing stage could throw. This was not demonstrated as a reachable default bridge bypass. | Validate every implementation of the structured interface and require explicit successful completion. Exhaustive stage map forces new contract stages into the gate.                                                                                                    | Interface group: all and each individual skipped stage, missing stage, all verified. All now reject or accept as specified. Pass.                 |
| P1 default bridge: independent failures   | `python/verify_ap2_structured.py`, `verify_request`                                              | Root time evaluation was nested under successful leaf verification. Corrupting the leaf suppressed authenticated root expiry.                                  | Collect authenticated root and leaf payloads independently; evaluate available time evidence outside leaf processing. Preserve root expiry bounds on leaf failure.                                                                                                      | Independent failures group: root expiry plus bad leaf; nonce plus EIP signature plus settlement failures. Controlled order preserved. Pass.       |
| P2 false rejection: optional website      | `src/schemas.ts`, Merchant schema; `src/types.ts`                                                | Website was mandatory despite optional status in the frozen mapping and upstream model.                                                                        | Make website optional, retain URL validation when supplied and matching nonempty ID semantics.                                                                                                                                                                          | Optional merchant group: omitted website accepts; invalid website and missing identity reject. Pass.                                              |
| Independence: unsigned producer label     | `src/evaluator.ts`, context check; `src/constants.ts`                                            | An unsigned descriptive label was treated as mandatory producer identity. No cryptographic or controlling profile requirement justified it.                    | Remove the equality condition and exported expected label. Retain type/shape validation, time context and real runtime source pins. No replacement trusted implementation label.                                                                                        | Renaming only the label now accepts. Pass.                                                                                                        |

## Dependency model for failure collection

1. Raw JSON/JCS and envelope validity precede semantic evaluation. Invalid case shape reports
   `INPUT_SCHEMA_INVALID`; arbitrary fragments do not become partially trusted cases.
2. Root signature verification supplies the holder key and independently authenticated root times.
3. Closed signature verification depends on that holder key. Terminal binding has its own status.
   Authenticated time checks do not require successful audience/nonce binding to report invalid
   time.
4. Commerce, constraints and AP2 cross field bindings require both verified mandates and terminal
   binding. A corrupted token's unauthenticated claim contents do not drive these diagnostics.
5. Receipt verification uses its separately supplied key. Receipt reference comparisons require the
   leaf reference; its signature and transaction checks remain separately applicable.
6. x402, EIP signature and settlement checks use the schema validated payment input. Authenticated
   root expiry remains a known upper bound even if the terminal signature is invalid.

The existing controlled order and deduplication remain unchanged. Normalised versus signed claim
consistency diagnostics remain available. No failure list is taken from a reference verifier.

## Unresolved specification boundaries

### Concealed restrictive claims

The frozen documents require enforcement of signed constraints, but do not specify how an
implementation establishes that every authority limiting restriction was disclosed. The pinned SDK
and generic SD-JWT processing allow undisclosed digest placeholders, including decoys. The
controlling documents do not give an unambiguous completeness rule for that distinction.

The independently constructed root with an undisclosed restrictive amount condition still accepts;
disclosing that condition produces `AP2_CONSTRAINT_VIOLATION`. This remains an explicit
specification question, not a fixed security guarantee. The observation test preserves it. Presented
disclosure authentication does not prove complete disclosure of all possible claims.

Minimum proposed rule: the profile must define a nonselective authoritative restriction set, or
require every authority limiting restriction to be disclosed with a verifiable completeness
mechanism, and require rejection when completeness cannot be established. It must also specify where
decoys and selective disclosure inside allowed sets remain legitimate. This proposal is not silently
imposed as a new v0.3 policy.

### Resource authenticity

The schema contains the payload's resource, but no separately authenticated expected resource.
Changing a syntactically valid resource URL and recomputing the unsigned input hash still accepts.
The evaluator validates shape; it does not claim resource authenticity or a signed binding that does
not exist. A stronger profile needs a trusted expected value or signed digest.

### Schema failure applicability

The frozen profile does not fully define the independent checks required after a case schema
failure. This revision retains schema rejection without speculative downstream codes. An unknown
resource member combined with unsuccessful settlement therefore reports only `INPUT_SCHEMA_INVALID`.
A future clarification should publish prerequisites for each failure code.

## Regression provenance and commits

1. `4353a5cb3c130a1168055b56af95976e47819c06`: tests first. All 61 tests ran against evaluator
   source identical to the frozen implementation. There were 37 failures and 24 passing controls.
2. `418edbb51d60d95da41e3164b71b9124e65365c3`: strict JSON/JCS boundaries. All 13 selected parser
   and raw input tests passed; unrelated tests were excluded by the focused selector.
3. `b4205e74586113a0ada2b38cf4f27eae8f20a21e`: the cohesive signed authority contract, disclosure
   checks, explicit completion gate, optional website and independence cleanup. The temporal
   evidence transport and the consuming gate changed atomically.
4. Subsequent commits record evidence, documentation and the report generator, not evaluator logic.

The signing helper uses fixed public test scalars with deterministic ES256 signatures and viem EIP
signatures. It uses no Pulse or AP2 issuance implementation. Full bridge regressions run the actual
Python verifier; interface only tests and syntax only Python tests identify themselves. Four
supplementary tests document three specification boundaries and deterministic signing.

## Validation commands and local results

Environment: Windows, Node 24.18.0, pnpm 10.18.1, Python 3.12.3, pinned AP2 SDK and audited Python
dependencies. PostgreSQL 18.1 ran as an isolated local test cluster on loopback port 55482, using
only synthetic data, and was stopped after testing. GitHub CI uses PostgreSQL 18.4.

| Command                                                                                                                                                                      | Result                                                                                  |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| `pnpm install --frozen-lockfile`                                                                                                                                             | Pass; no dependency or lockfile changes                                                 |
| `pnpm audit --prod --audit-level high`                                                                                                                                       | Pass; four moderate findings remain, no high or critical findings; audit unchanged      |
| `python -B -m pip_audit --timeout 20 --progress-spinner off`                                                                                                                 | Pass; no known vulnerabilities                                                          |
| `pnpm format:check`                                                                                                                                                          | Pass                                                                                    |
| `pnpm lint`                                                                                                                                                                  | Pass                                                                                    |
| `pnpm typecheck`                                                                                                                                                             | Pass                                                                                    |
| `pnpm test:unit`                                                                                                                                                             | 168 pass                                                                                |
| `pnpm test:pulse`                                                                                                                                                            | 89 TypeScript tests pass; structured Python self test and 16 Python boundary tests pass |
| `pnpm test:ap2-official`                                                                                                                                                     | Production AP2 bridge self test passes, unchanged                                       |
| `pnpm test:integration` with the test PostgreSQL URL                                                                                                                         | 29 pass, none skipped                                                                   |
| `pnpm test:kya` with the test PostgreSQL URL                                                                                                                                 | 62 pass, none skipped                                                                   |
| `pnpm conformance`                                                                                                                                                           | Pass across five rails                                                                  |
| `pnpm conformance:kya`                                                                                                                                                       | One test passes                                                                         |
| `pnpm build`                                                                                                                                                                 | Pass                                                                                    |
| `pnpm evidence:verify`                                                                                                                                                       | Pass                                                                                    |
| `pnpm evidence:kya:verify`                                                                                                                                                   | Pass                                                                                    |
| `pnpm schemas:generate`, `pnpm evidence:generate`, `pnpm evidence:kya:generate`, then `git diff --exit-code -- schemas fixtures evidence` before adding remediation evidence | Pass; existing generated artefacts unchanged                                            |

Initially, the PostgreSQL suites ran without a database and skipped their database cases. The
reported totals above are from the subsequent complete database backed runs. The sandboxed Python
audit did not complete; its network enabled rerun passed. Native `pnpm exec vitest` did not resolve
the executable, so focused runs used `node_modules/.bin/vitest.CMD`. The normal repository
`pnpm test:pulse` command works. These setup failures were not counted as passes.

GitHub quality, CodeQL and secret scanning are required separately on the draft PR. Local totals do
not represent those hosted checks. Consult the PR checks for the exact head revision and run IDs.
The patch also received a fresh independent read only review; the reviewer reported no concrete
surviving bypass or compatibility regression, without inspecting reference expectations.

## Blinded corpus replay

The exact original raw bytes were verified against the frozen SHA before blinding. The
[new record](reproduction.json) contains 80 unique results, 20 accept and 60 reject. Machine
comparison with Inntris's previously frozen public record found no changed decisions or ordered
failure lists. This compares independent results, not fixture expected values. No external checker
output was generated for this revision.

From the repository root, with the pinned runtimes available, reproduce into new output paths:

```bash
pnpm pulse:blind -- --source frozen-cases.json --output evaluator-input.json
pnpm pulse:evaluate -- --input evaluator-input.json --record remediation-reproduction.json --implementation-commit b4205e74586113a0ada2b38cf4f27eae8f20a21e --organization Inntris --published-url https://github.com/Inntris/inntris-x402-policy-adapter/blob/codex/pulse-ap2-x402-adversarial-remediation/evidence/pulse-ap2-x402-remediation/reproduction.json --notes "Independent remediation replay; no external Pulse validator run"
```

The local evidence run used `node packages/pulse-conformance-evaluator/dist/cli.js evaluate` with
the same flags, `.dev/pulse-remediation-blinded.json` as input, the committed record path as output
and `--python .venv/Scripts/python.exe`. The raw fixture was reused unchanged from the previous
local qualification download and rehashed by the blinding command.

To regenerate the named regression summary after collecting Vitest JSON reports:

```bash
node --import tsx test/pulse/report-regressions.ts .dev/pulse-remediation-red.json .dev/pulse-remediation-green.json regression-results.json b4205e74586113a0ada2b38cf4f27eae8f20a21e
```

## Security conclusion

The confirmed P0 and P1 counterexamples no longer reproduce in the regression suite. The optional
website case now accepts, mandatory cryptographic stages cannot silently degrade to acceptance, and
all previously recorded corpus results remain unchanged. The three explicit specification boundaries
above remain limitations. This is evidence, not a proof of correctness or freedom from undiscovered
counterexamples. No production readiness or live settlement claim is made. No automatic merge or
public Pulse issue update is authorised by this evidence.
