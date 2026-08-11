import { hashCanonical, systemClock, type InntrisActionV1 } from "@inntris/decision-core";
import { Decimal } from "decimal.js";
import { createRevocationChecker, createSafeFetch, type SafeFetch } from "@kya-os/mcp/card";

import { assertNoReservedKyaExtension, completeVerifiedBinding } from "./binding.js";
import { KyaAuthorityError } from "./errors.js";
import { StrictKyaFinancialActionMapper } from "./mapper.js";
import { didMethodOf, hashKyaAuthorityPolicy } from "./policy.js";
import {
  KYA_PROTOCOL_VERSION,
  KYA_REFERENCE_PACKAGE,
  KYA_REFERENCE_PACKAGE_VERSION,
  KyaAuthorityPresentationSchema,
} from "./schemas.js";
import type {
  KyaAuthorityVerifier,
  KyaDelegationVerifier,
  KyaFinancialAction,
  KyaFinancialActionMapper,
  KyaRequestProofVerifier,
  KyaNonceStore,
  KyaDidResolver,
  VerifiedKyaAuthority,
  VerifyKyaAuthorityInput,
} from "./types.js";
import { ModernKyaDelegationVerifier } from "./delegation.js";
import { OfficialEddsaJcs2022Verifier } from "./delegation-signature.js";
import { ProductionKyaDidResolver } from "./did-resolver.js";
import { UpstreamKyaRequestProofVerifier } from "./request-proof.js";
import {
  DisabledLegacyKyaVerificationAdapter,
  UpstreamLegacyKyaVerificationAdapter,
  type LegacyKyaVerificationAdapter,
} from "./legacy.js";

function requireProfile(input: VerifyKyaAuthorityInput): void {
  if (!input.authorityPolicy.profiles.includes(input.presentation.profile)) {
    throw new KyaAuthorityError(
      "KYA_PRESENTATION_INVALID",
      "presentation",
      "KYA presentation profile is not accepted by policy",
    );
  }
  if (!input.authorityPolicy.expected_audiences.includes(input.expectedAudience)) {
    throw new KyaAuthorityError(
      "KYA_AUDIENCE_MISMATCH",
      "request_proof",
      "Expected KYA audience is not authorised by policy",
    );
  }
}

function requireAcceptedDid(did: string, policy: VerifyKyaAuthorityInput["authorityPolicy"]): void {
  const method = didMethodOf(did);
  if (method === undefined || !policy.accepted_did_methods.includes(method)) {
    throw new KyaAuthorityError(
      "KYA_AGENT_IDENTITY_MISMATCH",
      "delegation",
      "Delegation uses an unaccepted DID method",
    );
  }
}

function requireAssurance(actual: "L3" | "L3-minus", required: "L3" | "L3-minus"): void {
  if (required === "L3" && actual !== "L3") {
    throw new KyaAuthorityError(
      "KYA_PROOF_ASSURANCE_INSUFFICIENT",
      "request_proof",
      "KYA request proof assurance is below policy",
    );
  }
}

function requirePrincipalJoin(
  action: InntrisActionV1,
  responsiblePartyDid: string,
  principalDid: string | undefined,
  policy: VerifyKyaAuthorityInput["authorityPolicy"],
): string | undefined {
  const expected =
    policy.principal_source === "responsible_party" ? responsiblePartyDid : principalDid;
  if (expected === undefined || action.principal_id !== expected) {
    throw new KyaAuthorityError(
      "KYA_PRINCIPAL_MISMATCH",
      "financial_join",
      "Inntris principal does not match verified KYA accountability",
    );
  }
  return policy.principal_source === "card_principal" ? expected : undefined;
}

function requireFinancialJoin(
  action: InntrisActionV1,
  financial: KyaFinancialAction,
  delegation: Awaited<ReturnType<KyaDelegationVerifier["verify"]>>,
  input: VerifyKyaAuthorityInput,
): void {
  if (action.agent_id !== delegation.agentDid) {
    throw new KyaAuthorityError(
      "KYA_AGENT_IDENTITY_MISMATCH",
      "financial_join",
      "Inntris agent_id does not match verified KYA proof DID",
    );
  }
  if (!delegation.allowedActions.includes(financial.action)) {
    throw new KyaAuthorityError(
      "KYA_ACTION_NOT_DELEGATED",
      "financial_join",
      "payments.transfer is not delegated",
    );
  }
  if (action.transaction.amount !== financial.amount) {
    throw new KyaAuthorityError(
      "KYA_AUTHORITY_BINDING_MISMATCH",
      "financial_join",
      "KYA and Inntris payment amounts differ",
    );
  }
  const payeeMapped = input.authorityPolicy.payee_bindings?.some(
    (binding) =>
      binding.inntris_payee === action.transaction.payee && binding.kya_payee === financial.payee,
  );
  if (action.transaction.payee !== financial.payee && payeeMapped !== true) {
    throw new KyaAuthorityError(
      "KYA_AUTHORITY_BINDING_MISMATCH",
      "financial_join",
      "KYA and Inntris payment payees differ",
    );
  }
  const resource = input.authorityPolicy.resource_bindings.find(
    (binding) => binding.inntris_resource === action.protocol_reference.resource,
  );
  if (
    resource?.kya_invocation_target !== financial.resource ||
    resource.kya_invocation_target !== delegation.invocationTarget
  ) {
    throw new KyaAuthorityError(
      "KYA_INVOCATION_TARGET_MISMATCH",
      "financial_join",
      "KYA resource is not exactly mapped to the Inntris action resource",
    );
  }
  const currency = input.authorityPolicy.currency_bindings.find(
    (binding) => binding.inntris_asset === action.transaction.asset,
  );
  if (delegation.maxAmount === undefined && input.authorityPolicy.require_max_amount) {
    throw new KyaAuthorityError(
      "KYA_MAX_AMOUNT_REQUIRED",
      "financial_join",
      "KYA MaxAmount is required by policy",
    );
  }
  if (
    currency?.kya_currency !== financial.currency ||
    currency.kya_currency !== delegation.currency
  ) {
    throw new KyaAuthorityError(
      "KYA_CURRENCY_MISMATCH",
      "financial_join",
      "KYA currency is not explicitly mapped to the Inntris asset",
    );
  }
  if (
    delegation.maxAmount !== undefined &&
    new Decimal(action.transaction.amount).greaterThan(delegation.maxAmount)
  ) {
    throw new KyaAuthorityError(
      "KYA_AMOUNT_EXCEEDS_DELEGATION",
      "financial_join",
      "Payment amount exceeds delegated KYA MaxAmount",
    );
  }
}

export interface DefaultKyaAuthorityVerifierOptions {
  requestProof: KyaRequestProofVerifier;
  delegation: KyaDelegationVerifier;
  mapper?: KyaFinancialActionMapper;
  legacy?: LegacyKyaVerificationAdapter;
}

export class DefaultKyaAuthorityVerifier implements KyaAuthorityVerifier {
  readonly #mapper: KyaFinancialActionMapper;

  constructor(readonly options: DefaultKyaAuthorityVerifierOptions) {
    this.#mapper = options.mapper ?? new StrictKyaFinancialActionMapper();
  }

  async verify(input: VerifyKyaAuthorityInput): Promise<VerifiedKyaAuthority> {
    const presentation = KyaAuthorityPresentationSchema.parse(input.presentation);
    if (presentation.profile !== "entity-card-v1") {
      assertNoReservedKyaExtension(input.action);
      requireProfile({ ...input, presentation });
      return (this.options.legacy ?? new DisabledLegacyKyaVerificationAdapter()).verify({
        presentation,
        action: input.action,
        policy: input.authorityPolicy,
        expectedAudience: input.expectedAudience,
        now: input.now ?? systemClock.now(),
      });
    }
    assertNoReservedKyaExtension(input.action);
    requireProfile({ ...input, presentation });
    const now = input.now ?? systemClock.now();
    const proof = await this.options.requestProof.verify({
      proof: presentation.request_proof,
      request: presentation.request,
      expectedAudience: input.expectedAudience,
      ...(presentation.token_cnf_jkt === undefined
        ? {}
        : { tokenCnfJkt: presentation.token_cnf_jkt }),
    });
    const financial = this.#mapper.map(presentation.request);
    const delegation = await this.options.delegation.verify({
      presentation,
      proof,
      policy: input.authorityPolicy,
      now,
    });

    requireAcceptedDid(proof.did, input.authorityPolicy);
    requireAcceptedDid(delegation.responsiblePartyDid, input.authorityPolicy);
    if (delegation.principalDid !== undefined) {
      requireAcceptedDid(delegation.principalDid, input.authorityPolicy);
    }
    if (!input.authorityPolicy.responsible_parties.includes(delegation.responsiblePartyDid)) {
      throw new KyaAuthorityError(
        "KYA_RESPONSIBLE_PARTY_NOT_ALLOWED",
        "delegation",
        "KYA Responsible Party is not allowlisted",
      );
    }
    requireAssurance(proof.assurance, input.authorityPolicy.min_proof_assurance);
    if (!input.authorityPolicy.allowed_actions.includes(financial.action)) {
      throw new KyaAuthorityError(
        "KYA_ACTION_NOT_DELEGATED",
        "financial_join",
        "KYA action is not permitted by authority policy",
      );
    }
    const principalDid = requirePrincipalJoin(
      input.action,
      delegation.responsiblePartyDid,
      delegation.principalDid,
      input.authorityPolicy,
    );
    requireFinancialJoin(input.action, financial, delegation, input);

    const binding = completeVerifiedBinding({
      version: "inntris-kya-authority-binding-v1",
      status: "verified",
      profile: presentation.profile,
      protocol_version: KYA_PROTOCOL_VERSION,
      reference_implementation: {
        package: KYA_REFERENCE_PACKAGE,
        version: KYA_REFERENCE_PACKAGE_VERSION,
      },
      authority_policy_hash: hashKyaAuthorityPolicy(input.authorityPolicy),
      presentation_hash: hashCanonical(presentation),
      proof_hash: proof.proofHash,
      request_hash: proof.requestHash,
      delegation_chain_hash: delegation.chainHash,
      entity_card_hash: delegation.entityCardHash ?? null,
      agent_did: proof.did,
      responsible_party_did: delegation.responsiblePartyDid,
      principal_did: principalDid ?? null,
      proof_assurance: proof.assurance,
      invocation_target: delegation.invocationTarget,
      allowed_action: financial.action,
      max_amount: delegation.maxAmount ?? null,
      currency: delegation.currency ?? null,
      delegation_depth: delegation.delegationDepth,
      revocation_fresh: delegation.revocationFresh,
      signatures_verified: true,
      verified_at: now.toISOString(),
      authority_expires_at: delegation.authorityExpiresAt.toISOString(),
    });
    return {
      binding,
      agentDid: proof.did,
      responsiblePartyDid: delegation.responsiblePartyDid,
      ...(principalDid === undefined ? {} : { principalDid }),
      action: financial.action,
      ...(delegation.maxAmount === undefined ? {} : { maxAmount: delegation.maxAmount }),
      ...(delegation.currency === undefined ? {} : { currency: delegation.currency }),
      invocationTarget: delegation.invocationTarget,
      authorityExpiresAt: delegation.authorityExpiresAt,
    };
  }
}

export function createProductionKyaAuthorityVerifier(options: {
  nonceStore: KyaNonceStore;
  resolver?: KyaDidResolver;
  safeFetch?: SafeFetch;
  clock?: import("@inntris/decision-core").Clock;
}): DefaultKyaAuthorityVerifier {
  const resolver = options.resolver ?? new ProductionKyaDidResolver();
  const safeFetch = options.safeFetch ?? createSafeFetch();
  const clock = options.clock;
  const requestProof = new UpstreamKyaRequestProofVerifier({
    resolver,
    nonceStore: options.nonceStore,
    ...(clock === undefined ? {} : { clock }),
  });
  const revocation = createRevocationChecker({
    fetch: safeFetch,
    ...(clock === undefined ? {} : { now: () => clock.now().getTime() }),
  });
  return new DefaultKyaAuthorityVerifier({
    requestProof,
    delegation: new ModernKyaDelegationVerifier({
      signatures: new OfficialEddsaJcs2022Verifier(resolver),
      revocation,
    }),
    legacy: new UpstreamLegacyKyaVerificationAdapter({ resolver, requestProof, revocation }),
  });
}
