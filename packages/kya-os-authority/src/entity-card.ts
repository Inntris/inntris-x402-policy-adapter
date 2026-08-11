import {
  EntityCardSchema,
  verifyCard,
  type AttestationVerifier,
  type EntityCard,
  type RevocationChecker,
} from "@kya-os/mcp/card";

import { KyaAuthorityError } from "./errors.js";

export interface KyaEntityCardPrincipalVerifier {
  verify(input: {
    card: unknown;
    expectedAgentDid: string;
    responsiblePartyDid: string;
  }): Promise<string>;
}

export class UpstreamEntityCardPrincipalVerifier implements KyaEntityCardPrincipalVerifier {
  constructor(
    readonly options: {
      attestationVerifier: AttestationVerifier;
      revocation: RevocationChecker;
      trustedIssuers: readonly string[];
    },
  ) {}

  async verify(input: {
    card: unknown;
    expectedAgentDid: string;
    responsiblePartyDid: string;
  }): Promise<string> {
    const card: EntityCard = EntityCardSchema.parse(input.card);
    if (
      card.id !== input.expectedAgentDid ||
      card.responsibleParty !== input.responsiblePartyDid ||
      card.principal === undefined
    ) {
      throw new KyaAuthorityError(
        "KYA_PRINCIPAL_MISMATCH",
        "delegation",
        "Entity Card accountability does not match verified delegated authority",
      );
    }
    const principalAttestationIndexes = (card.attestations ?? [])
      .map((attestation, index) => ({ attestation, index }))
      .filter(
        ({ attestation }) =>
          attestation.type === "IdentityVerification" && attestation.subject === card.principal,
      )
      .map(({ index }) => index);
    if (principalAttestationIndexes.length === 0) {
      throw new KyaAuthorityError(
        "KYA_PRINCIPAL_MISMATCH",
        "delegation",
        "Entity Card principal lacks an identity attestation",
      );
    }
    const result = await verifyCard(card, {
      attestationVerifier: this.options.attestationVerifier,
      accountabilityVerifier: async (_card, context) => ({
        verified:
          _card.responsibleParty === input.responsiblePartyDid && context.proofDid === undefined,
        fresh: true,
      }),
      statusListChecker: this.options.revocation,
      trustedIssuers: this.options.trustedIssuers,
    });
    if (
      !result.ok ||
      result.accountability?.verified !== true ||
      !principalAttestationIndexes.every((index) => result.attestations[index]?.verified === true)
    ) {
      throw new KyaAuthorityError(
        "KYA_PRINCIPAL_MISMATCH",
        "delegation",
        "Entity Card principal identity attestation was not verified",
      );
    }
    return card.principal;
  }
}
