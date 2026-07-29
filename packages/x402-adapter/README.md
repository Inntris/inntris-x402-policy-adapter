# `@inntris/x402-adapter`

A fail-closed guard around `@x402/core` 2.20.0. The package imports official x402
`PaymentRequirements` and `PaymentPayload` types and validates them with the SDK schemas.

Inntris does not settle the payment. A caller injects its settlement function, and that function is
not invoked unless evaluation, local verification and single-use consumption all succeed.
