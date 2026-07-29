# `@inntris/policy-engine`

Parses versioned YAML or JSON policies, hashes their validated meaning, evaluates them in
deterministic precedence order and returns unsigned policy results. The local provider then asks
`@inntris/decision-core` to sign an immutable decision.
