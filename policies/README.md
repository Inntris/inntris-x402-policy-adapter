# Policies

Policies are parsed from YAML or JSON, validated and then hashed as RFC 8785 canonical JSON. Source
formatting and comments are not part of policy meaning.

The committed demo policy permits one research resource on Base using USDC and the same merchant on
the AP2 card network using USD. It blocks amounts above `100.00` and requires human approval above
`75.00`.
