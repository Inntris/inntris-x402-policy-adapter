# Reference API

## Error model

A valid policy `BLOCK` or `REQUIRE_APPROVAL` is an HTTP `200` decision response.

| Status | Meaning                                                    |
| ------ | ---------------------------------------------------------- |
| `400`  | Malformed input                                            |
| `401`  | Optional bearer authentication failed                      |
| `409`  | A different execution reference attempted replay           |
| `422`  | A valid request cannot be consumed                         |
| `503`  | Signer, policy, nonce store or remote provider unavailable |

## Evaluate

`POST /v1/decisions/evaluate`

```json
{
  "action": {}
}
```

Response:

```json
{
  "decision": {}
}
```

## Verify

`POST /v1/decisions/verify`

```json
{
  "decision": {},
  "action": {},
  "expected_policy_version": "1"
}
```

The response contains boolean checks and stable failure reason codes.

## Consume

`POST /v1/decisions/consume`

```json
{
  "decision_id": "018f...",
  "action_hash": "sha256:...",
  "execution_ref": "facilitator-idempotency-reference"
}
```

The first unique execution succeeds. The same execution-reference retry returns `idempotent`. A
different reference returns HTTP `409` with `NONCE_ALREADY_CONSUMED`.

## Keys

`GET /.well-known/inntris-keys.json`

Only public verification material is returned.
