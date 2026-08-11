# KYA OS test fixtures

All identities are deterministic and TEST ONLY. The generator derives their private keys from
explicit test bytes and never writes private JWKs to fixtures. They must never be loaded by
production startup.

`valid-two-hop.json` and the proof fixtures contain genuine signatures. Mutation vectors identify
one exact change to the signed base presentation and the stable expected result. Focused tests apply
the same mutations to the cryptographic path.

Reproduce with `pnpm evidence:kya:generate` and verify hashes with `pnpm evidence:kya:verify`.
