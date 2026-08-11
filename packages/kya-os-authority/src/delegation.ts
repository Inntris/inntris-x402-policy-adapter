import { hashCanonical } from "@inntris/decision-core";
import {
  DelegationCredentialSchema,
  EntityCardSchema,
  evaluateDelegationChain,
  type DelegationCredential,
  type RevocationChecker,
} from "@kya-os/mcp/card";

import { KyaAuthorityError } from "./errors.js";
import { KyaAmountSchema, type KyaAuthorityPresentation } from "./schemas.js";
import type {
  KyaDelegationSignatureVerifier,
  KyaDelegationVerifier,
  VerifiedKyaDelegation,
  VerifiedKyaRequestProof,
} from "./types.js";
import type { KyaEntityCardPrincipalVerifier } from "./entity-card.js";

function expiryOf(chain: DelegationCredential[], proofExpires: number): Date {
  const values = [proofExpires * 1_000];
  for (const credential of chain) {
    if (credential.validUntil !== undefined) values.push(Date.parse(credential.validUntil));
    for (const caveat of credential.credentialSubject.caveats ?? []) {
      if (caveat.type === "ValidUntil" && caveat.date !== undefined) {
        values.push(Date.parse(caveat.date));
      }
    }
  }
  if (values.some(Number.isNaN)) {
    throw new KyaAuthorityError(
      "KYA_DELEGATION_EXPIRED",
      "delegation",
      "Delegation contains an invalid expiry",
    );
  }
  return new Date(Math.min(...values));
}

function effectiveMaxAmount(chain: DelegationCredential[]): {
  maxAmount?: string;
  currency?: string;
} {
  const leaf = chain.at(-1);
  const caveat = leaf?.credentialSubject.caveats?.find(
    (candidate) => candidate.type === "MaxAmount",
  );
  if (caveat === undefined) return {};
  if (typeof caveat.limit !== "string" || !KyaAmountSchema.safeParse(caveat.limit).success) {
    throw new KyaAuthorityError(
      "KYA_DELEGATION_INVALID",
      "delegation",
      "MaxAmount must be a canonical decimal with no more than six fractional digits",
    );
  }
  if (typeof caveat.currency !== "string" || caveat.currency === "") {
    throw new KyaAuthorityError(
      "KYA_CURRENCY_MISMATCH",
      "delegation",
      "MaxAmount currency is required",
    );
  }
  return { maxAmount: caveat.limit, currency: caveat.currency };
}

function delegationFailure(reasons: string[]): KyaAuthorityError {
  if (reasons.some((reason) => reason.includes("expired") || reason.includes("not yet valid"))) {
    return new KyaAuthorityError(
      "KYA_DELEGATION_EXPIRED",
      "delegation",
      "Delegation is outside its validity window",
    );
  }
  if (reasons.some((reason) => reason.includes("revoked"))) {
    return new KyaAuthorityError(
      "KYA_DELEGATION_REVOKED",
      "revocation",
      "Delegation chain is revoked",
    );
  }
  return new KyaAuthorityError(
    "KYA_DELEGATION_INVALID",
    "delegation",
    `Delegation chain rejected: ${reasons.join(", ")}`,
  );
}

export interface ModernKyaDelegationVerifierOptions {
  signatures: KyaDelegationSignatureVerifier;
  revocation: RevocationChecker;
  cardPrincipal?: KyaEntityCardPrincipalVerifier;
}

export class ModernKyaDelegationVerifier implements KyaDelegationVerifier {
  constructor(readonly options: ModernKyaDelegationVerifierOptions) {}

  async verify(input: {
    presentation: KyaAuthorityPresentation;
    proof: VerifiedKyaRequestProof;
    policy: import("./schemas.js").KyaAuthorityPolicyV1;
    now: Date;
  }): Promise<VerifiedKyaDelegation> {
    if (input.presentation.profile !== "entity-card-v1") {
      throw new KyaAuthorityError(
        "KYA_PRESENTATION_INVALID",
        "presentation",
        "Modern delegation verifier requires entity-card-v1",
      );
    }
    const chain = input.presentation.delegation_chain.map((credential) =>
      DelegationCredentialSchema.parse(credential),
    );
    for (const credential of chain) await this.options.signatures.verifyCredential(credential);

    const revocationResults = new Map<string, { revoked: boolean; fresh: boolean }>();
    for (const credential of chain) {
      const status = credential.credentialStatus;
      if (status === undefined) continue;
      const entry = {
        statusListCredential: status.statusListCredential,
        statusListIndex: status.statusListIndex,
      };
      const key = `${entry.statusListCredential}#${entry.statusListIndex}`;
      const checked = await this.options.revocation(entry);
      revocationResults.set(key, checked);
      if (checked.revoked) {
        throw new KyaAuthorityError(
          checked.fresh ? "KYA_DELEGATION_REVOKED" : "KYA_REVOCATION_UNAVAILABLE",
          "revocation",
          checked.fresh
            ? "Delegation chain contains a revoked credential"
            : "Delegation revocation status could not be established",
        );
      }
      if (input.policy.require_fresh_revocation && !checked.fresh) {
        throw new KyaAuthorityError(
          "KYA_REVOCATION_UNAVAILABLE",
          "revocation",
          "Fresh delegation revocation state could not be established",
        );
      }
    }

    const result = await evaluateDelegationChain(
      chain,
      async (entry) => {
        const key = `${entry.statusListCredential}#${entry.statusListIndex}`;
        const cached = revocationResults.get(key);
        if (cached === undefined) throw new Error("Missing preflight revocation result");
        return cached;
      },
      {
        maxDepth: input.policy.max_delegation_depth,
        now: () => input.now.getTime(),
      },
    );
    if (!result.ok) throw delegationFailure(result.reasons);
    if (input.policy.require_fresh_revocation && !result.fresh) {
      throw new KyaAuthorityError(
        "KYA_REVOCATION_UNAVAILABLE",
        "revocation",
        "Fresh delegation revocation state could not be established",
      );
    }
    if (result.leafInvoker !== input.proof.did) {
      throw new KyaAuthorityError(
        "KYA_AGENT_IDENTITY_MISMATCH",
        "delegation",
        "Delegation leaf invoker does not match the live request proof DID",
      );
    }
    if (result.responsibleParty === undefined || result.invocationTarget === undefined) {
      throw new KyaAuthorityError(
        "KYA_DELEGATION_INVALID",
        "delegation",
        "Delegation did not yield accountable authority",
      );
    }
    const card =
      input.presentation.entity_card === undefined
        ? undefined
        : EntityCardSchema.parse(input.presentation.entity_card);
    let principalDid: string | undefined;
    if (input.policy.principal_source === "card_principal") {
      if (card === undefined || this.options.cardPrincipal === undefined) {
        throw new KyaAuthorityError(
          "KYA_PRINCIPAL_MISMATCH",
          "delegation",
          "Policy requires a separately verified Entity Card principal",
        );
      }
      principalDid = await this.options.cardPrincipal.verify({
        card,
        expectedAgentDid: input.proof.did,
        responsiblePartyDid: result.responsibleParty,
      });
    }
    const amounts = effectiveMaxAmount(chain);
    return {
      agentDid: input.proof.did,
      responsiblePartyDid: result.responsibleParty,
      ...(principalDid === undefined ? {} : { principalDid }),
      invocationTarget: result.invocationTarget,
      allowedActions: result.allowedAction,
      ...amounts,
      authorityExpiresAt: expiryOf(chain, input.proof.expires),
      delegationDepth: result.depth,
      revocationFresh: result.fresh,
      chainHash: hashCanonical(chain),
      ...(card === undefined ? {} : { entityCardHash: hashCanonical(card) }),
    };
  }
}
