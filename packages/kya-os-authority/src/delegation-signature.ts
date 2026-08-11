import { createVerifyCryptosuite } from "@digitalbazaar/eddsa-jcs-2022-cryptosuite";
import { hashCanonical } from "@inntris/decision-core";
import { DelegationCredentialSchema, issuerDid } from "@kya-os/mcp/card";
import { decode, encode } from "base58-universal";

import { assertAssertionMethod } from "./did-resolver.js";
import { KyaAuthorityError } from "./errors.js";
import type { KyaDelegationSignatureVerifier, KyaDidResolver } from "./types.js";

function multikeyFromJwk(x: string): string {
  const key = Buffer.from(x, "base64url");
  if (key.length !== 32) throw new TypeError("Ed25519 public key must contain 32 bytes");
  return `z${encode(Uint8Array.from([0xed, 0x01, ...key]))}`;
}

function proofRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null) throw new TypeError("Proof must be an object");
  const proof = value as Record<string, unknown>;
  if (
    proof.type !== "DataIntegrityProof" ||
    proof.cryptosuite !== "eddsa-jcs-2022" ||
    proof.proofPurpose !== "assertionMethod" ||
    typeof proof.verificationMethod !== "string" ||
    typeof proof.proofValue !== "string" ||
    !proof.proofValue.startsWith("z")
  ) {
    throw new TypeError("Delegation requires a complete eddsa-jcs-2022 assertion proof");
  }
  return proof;
}

export class OfficialEddsaJcs2022Verifier implements KyaDelegationSignatureVerifier {
  constructor(readonly resolver: KyaDidResolver) {}

  async verifyCredential(input: unknown): Promise<void> {
    try {
      const credential = DelegationCredentialSchema.parse(input);
      const issuer = issuerDid(credential);
      const proof = proofRecord(credential.proof);
      const kid = proof.verificationMethod as string;
      const method = await this.resolver.resolveVerificationMethod(kid);
      const document = await this.resolver.resolveDidDocument(issuer);
      if (method.controller !== issuer || !kid.startsWith(`${issuer}#`)) {
        throw new TypeError("Delegation proof key is not controlled by the issuer");
      }
      assertAssertionMethod(document, kid);

      const publicKeyMultibase =
        method.publicKeyMultibase ??
        (method.publicKeyJwk?.kty === "OKP" && method.publicKeyJwk.crv === "Ed25519"
          ? multikeyFromJwk(method.publicKeyJwk.x)
          : undefined);
      if (publicKeyMultibase === undefined) {
        throw new TypeError("Delegation proof uses an unsupported key type");
      }

      const unsecured = structuredClone(credential) as Record<string, unknown>;
      delete unsecured.proof;
      const suite = createVerifyCryptosuite();
      const verificationMethod = {
        "@context": "https://w3id.org/security/multikey/v1",
        id: method.id,
        type: "Multikey",
        controller: method.controller,
        publicKeyMultibase,
      };
      const data = await suite.createVerifyData({
        cryptosuite: suite,
        document: unsecured,
        proof: structuredClone(proof),
      });
      const verifier = await suite.createVerifier({ verificationMethod });
      const valid = await verifier.verify({
        data,
        signature: decode((proof.proofValue as string).slice(1)),
      });
      if (!valid) throw new TypeError("Invalid eddsa-jcs-2022 signature");
    } catch (error) {
      throw new KyaAuthorityError(
        "KYA_DELEGATION_SIGNATURE_INVALID",
        "delegation_signature",
        "Delegation Data Integrity proof failed verification",
        { cause: error },
      );
    }
  }
}

export function delegationCredentialFingerprint(credential: unknown): string {
  return hashCanonical(DelegationCredentialSchema.parse(credential));
}
