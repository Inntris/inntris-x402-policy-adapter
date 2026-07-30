# Inntris Decision Envelope v1

## Canonical action

`InntrisActionV1` is the rail-independent policy input. The `v0.1.0` Phase 1 release supports the
`x402` rail. Current `main` also supports AP2 actions through the follow-on runtime gate. The core
package remains independent of both protocol SDKs.

Unknown fields are rejected. A versioned top-level `extensions` object is the only extension point.

## Action hash

```text
action_hash =
  "sha256:" +
  lowercase_hex(
    SHA-256(
      RFC8785_JCS(validated_inntris_action_v1)
    )
  )
```

The following values are bound:

1. Principal and agent.
2. Action type and rail.
3. Decimal amount, asset, network, payee and purpose.
4. Resource and protocol version or payment scheme.
5. For x402, the complete payment-requirements digest.
6. For x402, the payment-payload digest when a payload is available.
7. For AP2, the open intent, closed Checkout, closed Payment, checkout JWT and transaction hashes.

## Policy hash

The policy is parsed from YAML or JSON and validated before hashing. The validated object is the
preimage. YAML formatting and comments are not.

## Fingerprint preimage

The fingerprint payload contains every decision field except:

1. `decision_fingerprint`
2. `signing.signature`

It includes `signing.alg` and `signing.key_id`.

## Signature preimage

The Ed25519 signature covers the JCS bytes of every final decision field except `signing.signature`.
It therefore includes the calculated fingerprint.

## Immutability

A signed decision is never mutated. Human approval creates a new signed decision with a new ID,
nonce and expiry. The new decision sets `supersedes_decision_id` to the original `REQUIRE_APPROVAL`
ID.

## Canonical money

Amounts use a unique decimal string:

1. No sign.
2. No leading zeroes except `0`.
3. At least two fractional digits.
4. Up to eighteen fractional digits.
5. No redundant trailing zeroes beyond the second fractional digit.

Examples:

| Input      | Result   |
| ---------- | -------- |
| `4.50`     | Valid    |
| `4.5`      | Rejected |
| `4.500`    | Rejected |
| `0.000001` | Valid    |
| `01.00`    | Rejected |

## Reason codes

Reason codes are public contract values. Additive version-compatible changes are possible, but
existing codes must not be renamed to improve wording. New semantics require new codes.
