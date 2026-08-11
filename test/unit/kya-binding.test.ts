import {
  assertNoReservedKyaExtension,
  attachKyaAuthorityBinding,
  completeVerifiedBinding,
  KYA_AUTHORITY_EXTENSION_KEY,
  withoutKyaExtension,
} from "@inntris/kya-os-authority";
import { describe, expect, it } from "vitest";

import { buildKyaFixture, KYA_NOW } from "../kya-helpers.js";

describe("normalised KYA authority binding", () => {
  it("hashes, attaches and removes the reserved binding deterministically", async () => {
    const fixture = await buildKyaFixture();
    const binding = completeVerifiedBinding({
      version: "inntris-kya-authority-binding-v1",
      status: "verified",
      profile: "entity-card-v1",
      protocol_version: "1.0.0",
      reference_implementation: { package: "@kya-os/mcp", version: "1.12.0" },
      authority_policy_hash: `sha256:${"a".repeat(64)}`,
      presentation_hash: `sha256:${"b".repeat(64)}`,
      proof_hash: `sha256:${"c".repeat(64)}`,
      request_hash: `sha256:${"d".repeat(64)}`,
      delegation_chain_hash: `sha256:${"e".repeat(64)}`,
      entity_card_hash: null,
      agent_did: fixture.agent.did,
      responsible_party_did: fixture.root.did,
      principal_did: null,
      proof_assurance: "L3-minus",
      invocation_target: "did:web:api.example:payments",
      allowed_action: "payments.transfer",
      max_amount: "500.00",
      currency: "USD",
      delegation_depth: 1,
      revocation_fresh: true,
      signatures_verified: true,
      verified_at: KYA_NOW.toISOString(),
      authority_expires_at: new Date(KYA_NOW.getTime() + 60_000).toISOString(),
    });
    const bound = attachKyaAuthorityBinding(fixture.action, binding);
    expect(bound.extensions?.[KYA_AUTHORITY_EXTENSION_KEY]).toEqual(binding);
    expect(withoutKyaExtension(bound)).toEqual(fixture.action);
    expect(() => assertNoReservedKyaExtension(bound)).toThrow();
  });
});
