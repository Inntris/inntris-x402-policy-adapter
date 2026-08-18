# Stage 0.1 — F-10 operational check

**Question asked:** is `serviceApiKey` set in every deployed environment, and is the decision
endpoint externally reachable? If it has ever run unset and reachable, the receipts from that window
are provenance-uncertain and the window must be recorded.

## What I can and cannot answer

**I cannot answer the deployment half.** I have no access to any deployed environment, secret store,
hosting console, or runtime telemetry. Nothing in this session can observe what
`INNTRIS_SERVICE_API_KEY` is set to anywhere outside this repository, or whether any instance is
reachable from the public internet. **Do not read anything below as a statement that no exposed
window occurred.** The repository-side facts are recorded so that whoever does have that access can
answer the question quickly; the answer itself is owed by an operator.

## Repository-side facts

| Fact                                             | Evidence                                                                                                                                                                                                                                                                                  |
| ------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The credential is optional by construction       | `apps/demo-api/src/app.ts:129-136` — `authenticate` returns early when `options.serviceApiKey === undefined`, so the preHandler is a no-op.                                                                                                                                               |
| Blank is treated as unset                        | `apps/demo-api/src/start.ts:259` reads it through `configuredValue`, which maps `""` and whitespace to `undefined` (`start.ts:44-47`).                                                                                                                                                    |
| The shipped example leaves it blank              | `.env.example:14` — `INNTRIS_SERVICE_API_KEY=` with no value.                                                                                                                                                                                                                             |
| Only one configuration forces it                 | `app.ts:120-122` throws when a `reconciliationStore` is supplied without a key. A deployment without the PostgreSQL reconciliation store never hits that guard.                                                                                                                           |
| The default bind is loopback                     | `start.ts:273` — `INNTRIS_API_HOST ?? "127.0.0.1"`. External reachability requires an explicit host override or an external proxy. **This is the single most important mitigating fact, and it is a default, not an enforcement.**                                                        |
| No deployment artefact exists in the repository  | No `Dockerfile`, `docker-compose`, Helm chart, Terraform, or Kubernetes manifest anywhere in the tree. There is nothing here that pins the variable for any environment.                                                                                                                  |
| CI never starts the API                          | `.github/workflows/ci.yml` sets only `INNTRIS_TEST_POSTGRES_URL`; no workflow runs `demo:api` or `start.js`.                                                                                                                                                                              |
| The documentation describes auth as optional     | `docs/API.md:10` — "`401` \| Optional bearer authentication failed". The behaviour is documented, not an undocumented defect.                                                                                                                                                             |
| One documentation line is narrower than it reads | `docs/API.md:116` says the endpoint "requires `Authorization: Bearer …` and refuses unkeyed exposure". That is accurate **only** for `GET /v1/operations/unresolved`, and only because supplying a reconciliation store forces a key. It does not describe `POST /v1/decisions/evaluate`. |

## Measured behaviour

`D8:no-auth-default` — with no service key configured, `POST /v1/decisions/evaluate` returns a
signed `ALLOW` to an unauthenticated request. `D8:auth-enforced-when-configured` — once a key is
configured, anonymous and wrong-credential requests both return `401` and the correct credential
returns `200`, compared with `timingSafeEqual`.

## What an operator needs to check, and what to do with the answer

1. For every environment that has ever run `apps/demo-api`, was `INNTRIS_SERVICE_API_KEY` set to a
   non-blank value at process start? The value is read once at startup, so a mid-life change to the
   secret store does not retroactively protect earlier requests.
2. Was `INNTRIS_API_HOST` overridden away from `127.0.0.1`, or was the process fronted by a proxy,
   load balancer or tunnel? Loopback binding is the mitigating default; either of these removes it.
3. If both were true simultaneously for any period, record that window as **provenance-uncertain**:
   every receipt signed in it may have been minted by an unauthenticated caller who chose every
   policy-bearing field (F-6), including `principal_id` (F-5) and `assetDecimals` (F-1).

**Why this is an input to the receipt migration and not only a security check.** If such a window
exists, then receipts already in circulation carry an unknown provenance that the F-6 migration
cannot retroactively label — the receipts are signed and immutable. The migration would need a key
rotation with a cut-over date, so that verifiers can distinguish receipts signed before the boundary
from those signed after it. That is a materially larger change than adding a provenance field, and
whether it is required depends entirely on the answer to question 3.

## Recommended disposition

F-10's code fix (Stage 1) is small and unconditional: fail construction or startup without a
credential. It should not wait for the operational answer. The operational answer determines only
whether a key-rotation boundary must be added to the Stage 4 receipt work.
