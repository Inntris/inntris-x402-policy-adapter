# Frozen candidate local validation

Classification: **QUALIFIED**, limited to the requested local gates.

Tested source revision: `665e793b253c7c771e497ebc9eba2aa87356e270`.

Completed: 9 September 2026, 07:20:46.606 UTC. This evidence only follow up contains no evaluator,
test, production, fixture, dependency or workflow changes. The tested source remains the revision
above, not the subsequent commit which packages these records.

## Provenance

This is a composite of completed checks against one byte identical committed source, not one
uninterrupted run. The fresh checks started after the final source commit. All 379 tracked source
file SHA256 hashes matched before and after validation, and HEAD and the working tree remained
unchanged and clean throughout those executions.

These records supersede the earlier green report for validation provenance. They do not erase the
historical red report or the caveated green report that overlapped the final source edit. Both are
preserved, unchanged, in the archive. The previous committed remediation and original qualification
records are also unchanged.

The [manifest](manifest.json) indexes 68 byte preserved files in
[validation-artifacts.zip](validation-artifacts.zip). Every archived file has its original relative
path, byte length and SHA256. The archive contains the detailed report, exact commands, UTC start
and end times, exit statuses, counts, output logs, source hash inventories, original helper files,
failed attempts, fresh reproduction and post execution comparison. No PostgreSQL data directory,
dependency installation, raw Pulse fixture or blinded fixture is included.

Extract the archive into an empty directory, then open
`.dev/pulse-qualification-summary-20260909/README.md` for the complete report. Its relative links
resolve within the extracted archive. The `reproduction.json` retains its original metadata and
bytes, including its statement that the record was unpublished when generated.

## Completed checks

| Check                                      | Result                                |
| ------------------------------------------ | ------------------------------------- |
| Full evaluator suite                       | 89 TypeScript tests passed            |
| Separate adversarial and specification run | 65 passed, overlapping the full suite |
| Python boundary suite                      | 16 passed                             |
| Structured and production AP2 bridge tests | Passed                                |
| Repository unit suite                      | 168 passed                            |
| PostgreSQL integration suite               | 29 passed, no skips                   |
| KYA suite                                  | 62 passed, no skips                   |
| Multi rail conformance, including AP2      | All five rails passed                 |
| KYA conformance                            | One passed                            |
| Both existing evidence verifiers           | Passed                                |
| Frozen install, format, lint, types, build | Passed                                |
| Production high severity dependency audit  | Exit zero; seven moderate findings    |
| Python dependency audit                    | Exit zero; zero findings, 45 packages |
| Blinded corpus replay and comparison       | 80 executed, 80 unchanged             |

Do not add overlapping suite counts. The 65 test run is part of the 89 test evaluator suite; the
structured Python self test also invokes the 16 boundary tests. Earlier successful checks ran on 8
September against this exact committed source. The database, conformance, audit and replay gates
completed on 9 September.

## Database and environment deviations

Runner: Windows amd64, Node 24.18.0, pnpm 10.18.1 and Python 3.12.3. PostgreSQL 18.4 ran on Alpine
3.24.1, x86_64, kernel `6.6.87.2-microsoft-standard-WSL2`, using CI's exact image:

```text
postgres:18.4-alpine@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15
```

Successful database startup and readiness were established before the integration suite. The
database used synthetic data and loopback port 25432, and its container was stopped after use. This
was not the complete hosted Ubuntu CI environment.

Failed Windows PostgreSQL startup, Docker startup, interrupted Ubuntu package preparation and
Windows port binding attempts remain recorded as failures or incomplete attempts. Port 55484 lay
inside a Windows reserved range. A separate attempt used unreserved port 25432. No candidate changes
were made to obtain these passes. Frozen helpers were preserved; separately named helpers recorded
environment adaptations before execution and were not edited after replay results existed.

The esbuild lifecycle script warning follows the repository's existing `onlyBuiltDependencies: []`
policy. No scripts were enabled. The installed esbuild 0.28.1 executable passed a bounded transform
check, and the unchanged TypeScript build passed.

## Audit findings remain open

The required command `pnpm audit --prod --audit-level high` exited zero. The audit found seven
moderate vulnerabilities and no high or critical vulnerabilities. No finding was suppressed,
ignored, fixed or waived.

The separate JSON command exited one. Installed pnpm 10.18.1 code at `dist/pnpm.cjs:133722` returns
nonzero for any finding in JSON mode, before the severity threshold is applied in the non JSON
branch at line 133729. That reporting failure and its full output remain preserved; the exact
requested non JSON gate ran separately. The audit was not disabled or weakened.

| Package        | Moderate advisories                                                 | Reported patched version |
| -------------- | ------------------------------------------------------------------- | ------------------------ |
| qs 6.15.3      | `GHSA-x5fp-wj9c-mxmx`, `GHSA-4mjr-xmp4-gh2g`                        | 6.16.0                   |
| Fastify 5.10.0 | `GHSA-w2qp-rph6-63g4`, `GHSA-3m5p-2c4r-xxw2`                        | 5.12.1                   |
| Hono 4.13.1    | `GHSA-gqvv-2mrq-wpjv`, `GHSA-g6gw-c38x-mqfc`, `GHSA-crvj-82cr-hjcx` | 4.13.5                   |

The three Hono advisories were published on 8 September, increasing the previous count from four to
seven moderate findings. All affected dependency versions are inherited from base
`1f48fcff63d6373e88e97b5e7c49450682a64366`; manifests, workspace configuration, lockfile and Python
security overrides are unchanged. Attribution to the existing graph does not make a vulnerability
acceptable or establish whether it is reachable in a deployment. Full paths and advisory details are
in the archived audit report.

Python command: `python -B -m pip_audit --timeout 20 --progress-spinner off --format json`. It
exited zero with no known vulnerabilities among 45 dependencies, matching the previous result.

## Blind replay

The raw fixture SHA256 was verified before blinding. No hidden fixture expectations or external
Pulse implementation were used to adapt this candidate. The evaluator completed all 80 cases,
persisted its output, and recorded its hash before opening Inntris's previously frozen result.

| Event                 | UTC time                 |
| --------------------- | ------------------------ |
| Evaluation completed  | 2026-09-09T07:20:46.001Z |
| Output hash persisted | 2026-09-09T07:20:46.125Z |
| Comparison began      | 2026-09-09T07:20:46.252Z |
| Comparison completed  | 2026-09-09T07:20:46.351Z |

Result: 80 unique cases, 20 accept, 60 reject, 80 unchanged, zero missing, zero indeterminate and
zero unexpected differences. Decisions, ordered failure lists and input hashes all matched.

Fresh reproduction SHA256: `4f751cdb24792ba27880a04847b8af0f6e998c23db201599cd8ab74ba5caaa05`.

## Limits and merge gates

No new security counterexample was demonstrated by these executions. The
[documented specification boundaries](../README.md#unresolved-specification-boundaries) concerning
undisclosed restrictive claims, resource authenticity and failure applicability after schema
rejection remain open. This evidence is not proof of semantic completeness or freedom from
undiscovered vulnerabilities.

No external Pulse validator was invoked for this candidate. These local results do not establish
production readiness, live settlement, external endorsement, hosted CI success or permission to
merge. GitHub quality, CodeQL and secret scanning remain separate gates for the published PR head.
