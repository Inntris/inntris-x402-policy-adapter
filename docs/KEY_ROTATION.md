# Managed signing and key rotation

This runbook rotates a Decision Envelope Ed25519 key without putting private material in the
adapter, repository, logs or public registry.

## Preconditions

1. The signing broker accepts the contract documented in
   [`packages/managed-signing/README.md`](../packages/managed-signing/README.md).
2. The operator has authenticated the broker and independently obtained the new 32-byte Ed25519
   public key.
3. The current public registry is backed up and its publication path is understood.
4. Clocks on the API, broker and registry publication systems are synchronised.

## Rotation procedure

Assume key `decision-key-2026-01` is current, key `decision-key-2026-08` is new and the chosen
cutover time is `2026-08-01T00:00:00.000Z`.

1. Create the new key in the managed custody service. Do not export its private key.
2. Test a signature from the broker against the independently obtained public key.
3. Add the new public key to the registry as `active`, with `not_before` equal to the cutover time.
4. Publish the registry before cutover and confirm verifiers can retrieve the exact reviewed bytes.
5. At cutover, configure the API with the new key ID, pinned public key and broker endpoint, then
   perform a controlled restart.
6. Confirm startup succeeds. Startup fails if the signer identity, fingerprint, status or validity
   window does not match the registry.
7. Issue and independently verify one canary decision. Confirm its key ID and public-key
   fingerprint.
8. Mark the old registry entry `retired` and set `not_after` to the exact cutover time.
9. Republish the registry and verify both a pre-cutover decision and the new canary decision.
10. Disable the old key for signing in the custody service, while retaining its public registry
    entry for historical verification.

## Compromise procedure

Use `revoked`, rather than `retired`, when signatures made by a key must no longer be trusted.
Revocation intentionally causes historical decisions from that key to fail verification. Record the
incident time, affected key ID, registry version, known decision range and replacement procedure in
the incident system. Do not delete the entry, because deletion hides the reason verification fails.

## Rollback

Do not move `not_after` backwards after decisions have been issued. If the new broker path fails
before a canary decision is issued, restore the reviewed prior configuration and restart. If the new
key has already issued decisions, treat the event as a second controlled rotation with explicit
validity windows. Never enable a silent local-key fallback.

## Evidence to retain

1. Reviewed registry before and after cutover.
2. Public-key fingerprints obtained independently from the signing broker configuration.
3. Startup validation result and canary decision verification result.
4. Exact cutover timestamp and deployment identifier.
5. Custody-service audit event showing old-key disablement.

These artefacts demonstrate the adapter configuration and observed rotation. They do not by
themselves prove certified HSM custody or production operating effectiveness.
