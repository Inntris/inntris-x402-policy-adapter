# KYA OS security analysis

All controls fail closed. Tests named below are repository test files, not claims about a hosted
production deployment.

| Threat                            | Control                                                                             | Residual risk                                              | Coverage                                      |
| --------------------------------- | ----------------------------------------------------------------------------------- | ---------------------------------------------------------- | --------------------------------------------- |
| Forged DID                        | Resolve accepted DID methods and verify the published signing key                   | DID registry or DNS compromise remains external            | `kya-did-resolver`, `kya-request-proof`       |
| Kid and DID substitution          | Exact fragment, controller, DID membership and proof DID checks                     | Compromised authoritative DID document                     | `kya-request-proof`                           |
| Reserved extension spoofing       | Reject caller supplied `org.inntris/kya-os`                                         | A malicious executor can ignore Inntris                    | `kya-binding`, `kya-verifier`, `kya-api`      |
| Proof replay                      | Atomic DID and nonce consume with expiry                                            | Store compromise or incorrect clock                        | `kya-request-proof`, `kya-postgres-store`     |
| Request mutation                  | Upstream proof recomputes the canonical request hash                                | A different unprotected endpoint remains an operator error | `kya-request-proof`, `kya-conformance`        |
| Relay or confused deputy          | Exact audience and resource target checks                                           | Incorrect audience configuration                           | `kya-request-proof`, `kya-verifier`           |
| Invalid delegation signature      | Official eddsa JCS 2022 verifier on every modern hop                                | Upstream cryptosuite vulnerability                         | `kya-delegation-signature`                    |
| Broadened child delegation        | Structural action, caveat, expiry, continuity and target attenuation                | Unknown caveats must remain byte structurally equal        | `kya-delegation`                              |
| Revoked ancestor                  | Root to leaf status evaluation                                                      | Status publisher compromise                                | `kya-verifier`, upstream chain tests          |
| Stale revocation                  | Fresh status required by policy                                                     | Availability loss blocks valid work                        | `kya-verifier`                                |
| Missing MaxAmount                 | Policy can require a canonical cap                                                  | Misconfigured optional policy                              | `kya-verifier`                                |
| Currency confusion                | Explicit currency to asset mapping, no foreign exchange inference                   | Wrong operator mapping                                     | `kya-mapper`, `kya-verifier`                  |
| Resource confusion                | Exact URL to invocation target mapping                                              | Wrong operator mapping                                     | `kya-verifier`                                |
| Payee mismatch                    | Exact payee or explicit pair mapping                                                | Wrong explicit mapping                                     | `kya-verifier`, `kya-api`                     |
| Approval after revocation         | Fresh KYA verification before superseding decision                                  | Status service outage blocks approval                      | `kya-gate`                                    |
| Consumption after revocation      | Fresh KYA verification before consume                                               | External side effects still need executor enforcement      | `kya-gate`                                    |
| Proof reuse for another execution | Only the same successful execution reference can reuse state                        | Executor idempotency is still required                     | `kya-gate`, `kya-postgres-store`              |
| did:web SSRF                      | HTTPS safe fetch, public address checks, pinned connection, size and timeout limits | Public host compromise                                     | `kya-did-resolver`, upstream safe fetch tests |
| Status decompression bomb         | Pinned upstream revocation checker and response limits                              | Upstream parser defect                                     | upstream package tests and dependency pin     |
| Cache staleness                   | No DID cache by default, optional bounded cache only                                | Unsafe custom cache configuration                          | `kya-did-resolver`                            |
| Raw credential or PII leakage     | Persist minimised binding facts and hashes; prohibit raw proof logs                 | Application added logs can violate policy                  | API and store review, secret scan             |

The legacy profile has changed assurance semantics. It verifies one upstream legacy credential and a
live request proof, but it does not translate a failed modern chain. Its extra financial fields are
signed extensions required by this adapter and must be issued intentionally.
