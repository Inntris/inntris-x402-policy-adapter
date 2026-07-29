# Independent evidence verification

A regulator, customer or auditor can verify a decision with:

1. The signed decision JSON.
2. The exact action JSON.
3. A pinned Inntris public key registry.
4. The execution time and expected policy version when those checks are required.

They do not need an Inntris account, Inntris API access, the original database or a blockchain node.

## Offline command

```bash
node packages/decision-verifier/dist/cli.js decision evidence/allow.json \
  --action evidence/action.json \
  --keys fixtures/keys/registry.json \
  --expected-policy-version 1 \
  --at 2026-07-29T09:30:30.000Z
```

## Trust-root rule

The registry supplied by the evidence sender is not automatically trustworthy. A high-assurance
review pins a registry or public-key fingerprint obtained through an independently reviewed
publication channel.

The verifier checks:

1. Strict schemas.
2. Decision fingerprint.
3. Ed25519 signature.
4. Public-key fingerprint and validity window.
5. Exact action hash.
6. Decision lifetime at the supplied execution time.
7. Expected policy version.
8. Expected x402 requirements hash when supplied.

## Historical evidence

Expiry answers whether the decision was usable at an execution time. For historical evidence, pass
the recorded execution time with `--at`. This does not prove settlement. It proves that the signed
decision was valid at that time.

## Network behaviour

Local files are the default. The verifier never follows URLs embedded in a decision or action.
`--keys-url` is an explicit operator choice, requires HTTPS, rejects redirects and uses a bounded
timeout.
