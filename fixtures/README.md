# Test vectors

Every decision fixture contains:

1. The signed or deliberately altered decision.
2. The action used for verification.
3. The expected verification result.
4. The expected reason code.
5. Whether settlement may proceed.

| Fixture                   | Expected result                         |
| ------------------------- | --------------------------------------- |
| `valid-allow`             | Valid and executable once               |
| `valid-block`             | Cryptographically valid, not executable |
| `valid-require-approval`  | Cryptographically valid, not executable |
| `tampered-verdict`        | Fingerprint and signature failure       |
| `tampered-amount`         | Action hash mismatch                    |
| `tampered-payee`          | Action hash mismatch                    |
| `tampered-network`        | Action hash mismatch                    |
| `tampered-policy-hash`    | Fingerprint and signature failure       |
| `unknown-signing-key`     | Unknown signing key                     |
| `expired-decision`        | Expired at the supplied execution time  |
| `stale-policy-version`    | Expected policy version mismatch        |
| `replayed-decision`       | Second unique execution conflicts       |
| `x402-challenge-mismatch` | Payment requirements mismatch           |

The `kya-os/` subtree contains genuine signed KYA request proofs and delegation credentials plus
named mutation vectors for delegated authority checks. All identities are deterministic TEST ONLY
identities and are separate from every production or Inntris signing key.
