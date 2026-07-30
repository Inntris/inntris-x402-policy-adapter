# `@inntris/decision-verifier`

Offline decision verification with an explicitly supplied key registry. Network access is disabled
by default. The CLI only fetches a registry when the operator supplies `--keys-url`.

`verifyDecision` proves a decision is bound to an exact action. `verifySignedDecision` checks only
schema, fingerprint and signature, for callers that hold a decision but not its original action.
