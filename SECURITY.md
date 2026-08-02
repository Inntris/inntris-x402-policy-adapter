# Security policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability that could expose secrets, bypass policy or
permit duplicate settlement. Use GitHub private vulnerability reporting for this repository.

Include the affected commit, attack preconditions, reproduction steps, expected security invariant
and observed result. Do not include production credentials, signing seeds or customer data.

## Signing keys

1. Never commit or print a production signing seed.
2. Normal API startup requires an environment value, mounted file or injected provider.
3. `pnpm keys:generate:dev` writes a new local file with exclusive-create semantics and never prints
   the seed.
4. The committed fixture identity is deliberately public and is not a secret.
5. Production deployments should use a managed Ed25519 signer or HSM-backed provider when available.

Do not reuse the existing Inntris offline evidence-pack seed, live request-signing key or anchor
worker key for this reference service.

## Supported version

Security fixes are applied to the latest `main` branch and the most recent tagged release.

## Security invariants

Changes must preserve:

1. Strict schema validation before hashing.
2. RFC 8785 canonicalisation.
3. Exact x402 requirements binding.
4. Local signature and fingerprint verification.
5. Expiry and policy-version checks.
6. `ALLOW` as the only executable verdict.
7. Consumption before direct x402 settlement, or after confirmed settlement and before A2A delegate
   execution.
8. No remote-failure fallback.
9. No private material in logs, fixtures or Git history.
10. Constant-time API key comparison and rate limiting on the reference API.
11. A2A payment submission never counts as final settlement.
12. A2A task, payment, settlement and delegate execution references remain exact-bound.
13. AP2 mandate cryptography is verified by the pinned official SDK.
14. AP2 merchant, payee, amount, currency, checkout and expiry bindings are checked before policy.
15. A valid AP2 mandate still requires a current signed Inntris `ALLOW`.
16. An AP2 Payment Mandate is atomically claimed for one exact execution before the delegate runs.
17. AP2 Python dependencies use the committed security override set and pass `pip-audit`.
18. No EVM transaction reaches `wallet.signTransaction` without a locally verified and consumed
    `ALLOW` decision bound to every signing field.
19. Signed EVM bytes are parsed, exact-matched and signer-recovered before broadcast.
20. Inntris never receives or stores the injected wallet's private key.
21. Multi-rail conformance uses one policy and one verifier, and every exact action mutation must
    invalidate the original signed decision.
22. Mock card fixtures contain only opaque credential-reference hashes, never card credentials.
23. Production policy state commits nonce consumption and spend atomically and rechecks cumulative
    limits during the transaction.
24. MTP composition must consume and checkpoint matching MTP authority before local decision
    consumption and settlement.
25. MTP response loss must retry the same token and execution reference; a different reference must
    conflict.
26. The MTP agent signing key must not reuse the Decision Envelope, evidence-pack or anchor keys.

The test suite contains direct regression tests for these invariants.
