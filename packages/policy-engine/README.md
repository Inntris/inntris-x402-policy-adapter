# `@inntris/policy-engine`

Parses versioned YAML or JSON policies, hashes their validated meaning, evaluates them in
deterministic precedence order and returns unsigned policy results. The local provider then asks
`@inntris/decision-core` to sign an immutable decision.

The local provider also resolves human approvals. Resolving one issues a new signed decision whose
`supersedes_decision_id` references the original `REQUIRE_APPROVAL` decision, after re-evaluating
current policy, and it records cumulative spend on a decision's first consumption.
