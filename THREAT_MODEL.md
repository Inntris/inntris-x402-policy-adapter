# Threat model

## Assets

1. Organisational payment policy.
2. Decision signing identity and public key registry.
3. Action and x402 challenge integrity.
4. Single-use decision state.
5. Settlement ordering and execution reference.
6. Audit and evidence integrity.
7. A2A task binding, delegate execution state and action receipts.
8. AP2 mandate integrity, merchant trust roots, execution claims and action receipts.
9. EVM unsigned transaction integrity, injected wallet identity and broadcast ordering.
10. Mock card and paid MCP action-binding integrity in the conformance suite.

## Actors

1. Legitimate organisational agent and operator.
2. Prompt-injected or compromised agent.
3. Malicious resource server or altered 402 response.
4. Network attacker.
5. Compromised decision service.
6. Compromised or stale key registry.
7. Faulty or malicious executor.

## Trust boundaries

The agent, A2A task, x402 challenge, settlement observation and remote response cross untrusted
boundaries. The verifier trusts only the explicitly selected key registry. The executor trusts a
decision only after every local check passes and after the nonce store accepts consumption.

## Attack scenarios and mitigations

| Scenario                                               | Impact                                         | Mitigation                                                                                   |
| ------------------------------------------------------ | ---------------------------------------------- | -------------------------------------------------------------------------------------------- |
| Prompt-injected agent requests an unauthorised payment | Funds could move outside policy                | Strict policy checks, exact action binding and fail-closed settlement                        |
| Malicious or altered 402 challenge                     | Payment terms change after approval            | Official SDK validation plus requirements digest and action hash                             |
| Changed payee                                          | Redirected payment                             | Payee is in both the action and requirements digest                                          |
| Changed amount                                         | Overspend                                      | Canonical decimal amount and atomic x402 amount are both bound                               |
| Changed settlement network                             | Wrong-chain settlement                         | Network is in the action and requirements digest                                             |
| Replayed decision                                      | Duplicate settlement                           | Short TTL, nonce and atomic single-use store                                                 |
| Concurrent decisions exceed the daily limit            | Cumulative policy overspend                    | PostgreSQL rechecks the limit under a write lock and commits consumption with spend          |
| Same retry creates a duplicate                         | Duplicate execution                            | Stable execution reference, idempotent consumption and facilitator idempotency requirement   |
| Stale policy                                           | Old control set authorises payment             | Expected policy version and signed policy hash                                               |
| Expired approval                                       | Old authority is reused                        | Issued-at and expires-at checks at execution time, plus a bounded approval-resolution window |
| Approval resolved twice                                | Two live decisions for one approval request    | Resolution is single use and returns `APPROVAL_ALREADY_RESOLVED`                             |
| Approval granted after policy turned against it        | Human authority overrides current policy       | Policy is re-evaluated at resolution; a grant can still produce a signed `BLOCK`             |
| Issuer restates a subject it did not hash              | Genuine signature over inconsistent evidence   | Verifier cross-checks the decision's restated subject against the supplied action            |
| Compromised or unknown signing key                     | Forged decisions                               | Explicit registry, key fingerprint, validity window and local Ed25519 verification           |
| Changed verdict or reason                              | Evidence misrepresents the decision            | Fingerprint and signature cover verdict and reason codes                                     |
| Inntris unavailable                                    | Policy bypass                                  | Remote errors fail closed with `DECISION_SERVICE_UNAVAILABLE` and never fall back to allow   |
| Nonce store unavailable                                | Replay window                                  | Consumption failure blocks settlement                                                        |
| Partial failure after consume                          | Decision consumed but settlement state unknown | Reconcile by execution reference; never create a second reference                            |
| `PAYMENT_SUBMITTED` treated as settlement              | Delegate runs before payment is final          | Require explicit settled state and configured finality                                       |
| Settlement for task A is replayed for task B           | Paid authority unlocks the wrong task          | Bind task, context, resource, submission and settlement into action and execution hashes     |
| Unknown A2A settlement state                           | Delegate runs while payment outcome is unclear | Pause execution and require confirmation or reconciliation                                   |
| A2A delegate retry executes twice                      | Duplicate external side effect                 | Atomic execution claim, stable execution reference and completed-result replay               |
| Process fails after delegate claim                     | Delegate outcome is unresolved                 | Keep the claim in progress and block automatic retry pending reconciliation                  |
| Forged or altered AP2 mandate chain                    | Unauthorised payment                           | Pinned official SDK verifies every chain hop, disclosure and key binding                     |
| Valid AP2 mandate violates current policy              | Protocol authority bypasses organisation       | Exact mandate hashes feed a new policy decision and only `ALLOW` can execute                 |
| AP2 merchant, amount or checkout substitution          | Funds or terms are redirected                  | Exact merchant, payee, amount, currency and checkout hash checks                             |
| AP2 Payment Mandate replayed for another action        | Duplicate or substituted execution             | Atomic claim keyed by Payment Mandate hash and exact execution binding                       |
| AP2 verification becomes stale before execution        | Expired authority reaches the rail             | Verification age and mandate expiry are checked before and after policy evaluation           |
| AP2 trust registry unavailable                         | Unreviewed keys could be accepted              | Trust resolution fails closed                                                                |
| AP2 delegate fails after claim                         | Payment outcome is uncertain                   | Keep claim in progress and require reconciliation before retry                               |
| EVM transaction changes after authorisation            | Wallet signs different value, target or call   | Rebuild the action and verify the decision immediately before signing                        |
| Injected wallet signs different transaction bytes      | Authorised decision is applied to another tx   | Parse signed RLP, recover signer and compare every authorised field before broadcast         |
| Same unsigned EVM transaction gets another decision    | Duplicate signing or broadcast                 | Atomic claim keyed by canonical unsigned transaction hash                                    |
| Wallet or broadcast outcome becomes uncertain          | Automatic retry could duplicate a side effect  | Keep execution in progress and require reconciliation                                        |
| Card credential leaks into portable evidence           | Sensitive payment data is exposed              | Bind only an opaque credential-reference hash; reject unknown input fields                   |
| Paid MCP arguments change after policy evaluation      | A different tool action uses the decision      | Bind canonical tool-argument and payment-reference hashes                                    |
| Log tampering                                          | Misleading operational record                  | Signed portable decision remains independently verifiable                                    |
| Attacker-controlled key URL in evidence                | Trust-root substitution or SSRF                | Offline default; embedded URLs are ignored; explicit HTTPS URL only                          |
| Private key leaked in logs or repository               | Decision forgery                               | Explicit key loading, no startup generation, redacted logging and secret scanning            |

## Residual risks

1. An executor that ignores the guard can still settle. Enforcement belongs at the actual side
   effect boundary.
2. The in-memory reference stores are not durable or distributed.
3. A registry publisher can revoke or replace keys. Verifiers should pin a reviewed registry or
   public key for high-assurance workflows.
4. A valid decision proves authorisation, not successful settlement.
5. Consumption-before-settlement creates an outcome-reconciliation requirement when the rail times
   out.
6. Policy correctness depends on configuration review and a reliable durable spend-state adapter.
7. The in-memory A2A execution store cannot provide cross-process or crash recovery guarantees.
8. A delegate that ignores the supplied execution reference can still create an external duplicate.
9. The AP2 Python subprocess and pinned SDK add a deployment and upgrade governance boundary.
10. The in memory AP2 execution store cannot provide cross process or crash recovery guarantees.
11. The in-memory EVM execution store cannot provide cross-process or crash-recovery guarantees.
12. Mock card and MCP conformance proves envelope portability, not live processor or server
    enforcement.

## Out of scope claims

This repository does not claim HSM-grade custody, tested disaster recovery, guaranteed blockchain
finality, production availability, production latency or Base anchoring as a root of trust. It does
not implement a wallet, facilitator or payment rail.
