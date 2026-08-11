# KYA OS integration

KYA OS establishes cryptographic agent identity and delegated authority. Inntris does not replace
that delegation system. Inntris verifies the delegated authority as an input to its own runtime
organisational policy decision, binds the verified authority to the exact proposed financial action,
and controls whether that decision may be consumed before execution.

```text
KYA authority != Inntris ALLOW
```

## Composition

The primary `entity-card-v1` profile verifies a live holder of key request proof and a signed VC 2.0
and ZCAP delegation chain. The additive `legacy-v1` profile uses the upstream legacy
DelegationCredential or VC JWT verifier and stricter signed Inntris financial constraint fields. A
failed modern presentation is never retried as legacy.

The verified proof DID becomes `action.agent_id`. The root delegation issuer becomes the Responsible
Party and, under the default policy, `action.principal_id`. Selecting `card_principal` requires a
separately verified Entity Card IdentityVerification attestation.

The verifier recomputes all financial joins. Request amount and payee must match the x402 action.
Resource and currency use explicit policy mappings. Delegation target and `payments.transfer`
designation must match. The requested amount must not exceed the effective MaxAmount. No exchange
rate or asset equivalence is inferred.

Only a verified normalised binding is written to the reserved `org.inntris/kya-os` action extension.
Callers cannot supply that extension. The resulting action enters the unchanged Inntris policy
engine and unchanged `inntris-decision-v1` envelope.

## Lifecycle

Evaluation persists the verified binding against the signed decision. Human approval requires a new
proof and current delegation, then re evaluates current Inntris policy and issues a new bound
decision. Consumption also requires fresh authority. A successful revalidation is durable and a
retry with the same execution reference reuses it. A new execution reference requires a new proof.

Revocation, resolver or authority store uncertainty fails closed. Required mode will not start with
in memory nonce or authority state. The ordinary evaluation route issues a signed
`KYA_AUTHORITY_REQUIRED` block for protected resources, preventing route bypass. Ordinary approval
and consumption routes also reject decisions recorded as KYA protected. Those decisions must use the
KYA lifecycle routes with a fresh presentation.

## Data and claims boundary

Stored state contains hashes, DIDs, expiry, verified constraint facts and the bound action. It does
not store private keys, access tokens or raw identity attestations. Logs may carry hashes, decision
IDs, stages and stable reason codes, but not full proofs or credential chains.

The evidence proves local verification and reference composition. It does not prove a commercial
relationship with KYA OS, live funded settlement, production availability, certified key custody or
a conformance level beyond the exact tested proof assurance.
