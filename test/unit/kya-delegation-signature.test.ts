import { describe, expect, it } from "vitest";

import { OfficialEddsaJcs2022Verifier, ProductionKyaDidResolver } from "@inntris/kya-os-authority";

import { buildKyaFixture } from "../kya-helpers.js";

describe("KYA delegation signatures", () => {
  it("verifies an official eddsa-jcs-2022 Data Integrity proof", async () => {
    const fixture = await buildKyaFixture();
    const verifier = new OfficialEddsaJcs2022Verifier(new ProductionKyaDidResolver());
    await expect(verifier.verifyCredential(fixture.delegation)).resolves.toBeUndefined();
  });

  it("rejects a credential mutated after signing", async () => {
    const fixture = await buildKyaFixture();
    const verifier = new OfficialEddsaJcs2022Verifier(new ProductionKyaDidResolver());
    const mutated = structuredClone(fixture.delegation);
    const subject = mutated.credentialSubject as Record<string, unknown>;
    subject.allowedAction = ["payments.transfer", "wallet.sweep"];
    await expect(verifier.verifyCredential(mutated)).rejects.toMatchObject({
      reasonCode: "KYA_DELEGATION_SIGNATURE_INVALID",
    });
  });

  it("rejects missing and corrupt Data Integrity proofs", async () => {
    const fixture = await buildKyaFixture();
    const verifier = new OfficialEddsaJcs2022Verifier(new ProductionKyaDidResolver());
    const missing = structuredClone(fixture.delegation);
    delete missing.proof;
    await expect(verifier.verifyCredential(missing)).rejects.toMatchObject({
      reasonCode: "KYA_DELEGATION_SIGNATURE_INVALID",
    });

    const corrupt = structuredClone(fixture.delegation);
    const proof = corrupt.proof as Record<string, unknown>;
    proof.proofValue = `z${"1".repeat(88)}`;
    await expect(verifier.verifyCredential(corrupt)).rejects.toMatchObject({
      reasonCode: "KYA_DELEGATION_SIGNATURE_INVALID",
    });
  });
});
