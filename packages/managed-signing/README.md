# `@inntris/managed-signing`

Provider-neutral Ed25519 signing for a KMS, HSM, Vault or custody service that is exposed through an
operator-controlled HTTPS signing broker.

The broker receives canonical bytes plus their SHA 256 digest. It returns a base64url Ed25519
signature and the selected key ID. The adapter verifies that signature locally against a pinned
public key before any Decision Envelope is returned. A malformed, mismatched or unavailable signer
fails closed.

The broker contract is:

```json
{
  "version": "inntris-sign-request-v1",
  "alg": "Ed25519",
  "key_id": "decision-key-2026-08",
  "payload_base64url": "...",
  "payload_sha256": "sha256:..."
}
```

```json
{
  "version": "inntris-sign-response-v1",
  "alg": "Ed25519",
  "key_id": "decision-key-2026-08",
  "signature": "..."
}
```

The bearer credential, private key and broker response body are never logged. This reference adapter
does not claim that the downstream service is HSM grade.

## Rotation

Rotation uses explicit key-registry continuity and a controlled service restart:

1. Add the new public key as `active` before cutover.
2. Configure the signer to the new key and restart the service.
3. Confirm the service key matches the published registry.
4. Mark the old key `retired` with `not_after` equal to the cutover time.
5. Keep the retired public key published so historical decisions still verify.
6. Use `revoked` only when historical signatures must no longer be trusted.

The application chooses one static signer at startup. It does not rotate a key inside an in-flight
signing operation.
