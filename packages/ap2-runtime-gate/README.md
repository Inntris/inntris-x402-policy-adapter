# Inntris AP2 runtime gate

`@inntris/ap2-runtime-gate` is a fail closed execution boundary for autonomous AP2 payments. It
requires valid AP2 Checkout and Payment Mandate chains, binds the verified mandate hashes to an
Inntris action, applies current organisational policy, consumes the signed decision, claims the
Payment Mandate once and only then calls the injected payment delegate.

## Official AP2 boundary

The official AP2 implementation currently provides a Python SDK. This package therefore invokes a
small Python bridge which imports the official SDK for mandate chain, SD JWT, key binding, checkout
JWT and constraint verification. TypeScript does not reimplement AP2 cryptography.

The SDK dependency is pinned to:

```text
repository: https://github.com/google-agentic-commerce/AP2
commit: e1ea56db72a6385bce3e5c1112b3a56ce60acb43
protocol: 0.2
```

Install that exact revision in the Python environment used by the gate:

```bash
python -m pip install "git+https://github.com/google-agentic-commerce/AP2.git@e1ea56db72a6385bce3e5c1112b3a56ce60acb43"
python -m pip install --upgrade pip==26.2
python -m pip install --upgrade \
  -r packages/ap2-runtime-gate/python/security-overrides.txt
python -m pip_audit
```

The official commit currently declares older exact versions of `cryptography`, `jwcrypto` and
`pytest`. Those versions have published vulnerabilities. The reviewed override file keeps the
official AP2 source pinned while raising those dependencies to audited fixed releases. `pip` may
report that the installed versions differ from the upstream package metadata; CI treats a failed
self test or vulnerability audit as blocking.

Run `python packages/ap2-runtime-gate/python/self_test.py` to exercise real signed mandate chains.

## Intent representation

AP2 0.2 does not define a separate Intent Mandate. In the autonomous flow the user's intent is
represented by the open Checkout and open Payment Mandates. The gate verifies both complete open to
closed chains and commits their hashes into `intent_verification_hash`.

## Execution order

1. Validate the untrusted presentation.
2. Resolve issuer and merchant public keys from the configured trust provider.
3. Verify both mandate chains and the merchant checkout JWT with the pinned official SDK.
4. Enforce expiry, merchant, payee, amount, currency and checkout hash bindings.
5. Construct and hash the exact Inntris AP2 action.
6. Evaluate and locally verify the signed Inntris decision.
7. Require `ALLOW` and consume the decision.
8. Atomically claim the Payment Mandate hash for this exact execution.
9. Call the injected delegate.
10. Sign and persist an AP2 action receipt.

An exact completed retry returns the stored receipt and result. A changed binding conflicts. A
failed delegate leaves the claim in progress so an operator can reconcile the external outcome
without risking a duplicate payment.

## Production requirements

The default execution store is only an in memory reference implementation. Production deployment
requires a durable atomic store shared by every executor instance. The trust provider must resolve
reviewed issuer and merchant keys from operator controlled configuration. The payment delegate must
use the supplied execution reference as its own idempotency key.

The gate derives the policy network from the verified Payment Mandate instrument type. Currency
minor unit counts come from the operator controlled `currencyDecimals` configuration. Neither value
is accepted from the untrusted presentation.

Mandates and private keys must not be logged. The Node wrapper supplies a restricted environment to
the Python process, and the bundled bridge emits only a generic error class on failure.
