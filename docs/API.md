# Reference API

## Error model

A valid policy `BLOCK` or `REQUIRE_APPROVAL` is an HTTP `200` decision response.

| Status | Meaning                                                    |
| ------ | ---------------------------------------------------------- |
| `400`  | Malformed input                                            |
| `401`  | Optional bearer authentication failed                      |
| `409`  | A replayed execution reference or approval resolution      |
| `429`  | The per-process request limit was exceeded                 |
| `422`  | A valid request cannot be consumed or resolved             |
| `503`  | Signer, policy, nonce store or remote provider unavailable |

The reference API applies a per-process limit of 100 requests per minute and a 30 request limit to
each decision endpoint. Production deployments should enforce an additional distributed limit at the
trusted ingress.

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

## Approve

`POST /v1/decisions/approve`

```json
{
  "decision_id": "018f...",
  "granted": true,
  "approval_reference": "approval-ticket-4711",
  "approver_ids": ["user_finance_lead"]
}
```

The original `REQUIRE_APPROVAL` decision is never mutated. A resolution issues a new signed decision
whose `supersedes_decision_id` references it:

```json
{
  "success": true,
  "status": "superseded",
  "decision_id": "018f...",
  "decision": {}
}
```

Current organisational policy is re-evaluated at resolution time, so a granted approval still yields
a signed `BLOCK` decision when policy now denies the same action. A refused approval yields a signed
`BLOCK` decision carrying `HUMAN_APPROVAL_REFUSED`. Both are HTTP `200`, because a policy outcome is
not a technical failure.

Resolution is single use. A repeat returns HTTP `409` with `APPROVAL_ALREADY_RESOLVED`. A decision
that is not an open approval request returns HTTP `422` with `APPROVAL_NOT_PENDING`, and a request
resolved after its approval window closes returns HTTP `422` with `DECISION_EXPIRED`.

The approval window is `approval.request_ttl_seconds`, measured from the original decision's
`issued_at` and defaulting to 900 seconds. It is deliberately independent of `decision_ttl_seconds`,
because a human takes longer to answer than a signed decision stays valid.

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

## Unresolved operations

`GET /v1/operations/unresolved`

This read-only operational endpoint is available when a reconciliation store is configured. It
requires `Authorization: Bearer <INNTRIS_SERVICE_API_KEY>` and refuses unkeyed exposure.

Optional query parameters:

| Parameter        | Meaning                                                        |
| ---------------- | -------------------------------------------------------------- |
| `updated_before` | ISO 8601 timestamp; return operations older than this boundary |
| `limit`          | Integer from 1 to 500; defaults to 100                         |

The response contains `in_progress` and `outcome_unknown` operation records ordered from oldest to
newest. It does not expose a state-changing resolution route. Production resolution must use the
store contract from an authenticated operator service that has obtained authoritative rail evidence.
See [`RECONCILIATION.md`](RECONCILIATION.md).
