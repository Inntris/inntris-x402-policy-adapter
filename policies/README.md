# Policies

Policies are parsed from YAML or JSON, validated and then hashed as RFC 8785 canonical JSON. Source
formatting and comments are not part of policy meaning.

The committed demo policy permits one research resource on Base using USDC and the same merchant on
the AP2 card network using USD. It blocks amounts above `100.00` and requires human approval above
`75.00`.

## Time windows

`time_windows.start` and `time_windows.end` are inclusive local times in `time_windows.timezone`. A
window whose start is later than its end crosses local midnight, so `start: "22:00"` with
`end: "02:00"` permits 22:00 through 02:00. The weekday is always the weekday of the evaluated
instant, so the part of a crossing window after midnight belongs to the following day and that day
must also appear in `allowed_weekdays`.

## Approval window

`approval.request_ttl_seconds` is optional and controls how long a `REQUIRE_APPROVAL` decision stays
resolvable, measured from its `issued_at`. Policies that omit it use 900 seconds. Omitting it also
leaves the hashed policy object unchanged, so adding the field is what changes a policy hash.

## KYA delegated authority

`demo-kya-authority.yml` is a separate authority policy. It does not modify organisational payment
policy and does not add KYA as a rail. Its allowlist uses a deterministic public test DID only.
Required mode also needs PostgreSQL for atomic proof replay and durable authority lifecycle state.
