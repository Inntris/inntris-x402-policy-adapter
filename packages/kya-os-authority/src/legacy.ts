import { createPublicKey, verify as verifyBytes, type JsonWebKey } from "node:crypto";

import { hashCanonical, type InntrisActionV1 } from "@inntris/decision-core";
import type { RevocationChecker } from "@kya-os/mcp/card";
import {
  DelegationCredentialVerifier,
  canonicalizeJSON,
  prepareVcJwtCredential,
  type DIDResolver,
  type StatusListResolver,
} from "@kya-os/mcp/delegation";
import { validateDelegationCredential, type DelegationCredential } from "@kya-os/mcp/types";
import { Decimal } from "decimal.js";

import { completeVerifiedBinding } from "./binding.js";
import { KyaAuthorityError } from "./errors.js";
import { StrictKyaFinancialActionMapper } from "./mapper.js";
import { didMethodOf, hashKyaAuthorityPolicy } from "./policy.js";
import {
  KYA_PROTOCOL_VERSION,
  KYA_REFERENCE_PACKAGE,
  KYA_REFERENCE_PACKAGE_VERSION,
  KyaAmountSchema,
  type KyaAuthorityPolicyV1,
  type KyaLegacyAuthorityPresentation,
} from "./schemas.js";
import type { KyaDidResolver, KyaRequestProofVerifier, VerifiedKyaAuthority } from "./types.js";

export interface LegacyKyaVerificationAdapter {
  verify(input: {
    presentation: KyaLegacyAuthorityPresentation;
    action: InntrisActionV1;
    policy: KyaAuthorityPolicyV1;
    expectedAudience: string;
    now: Date;
  }): Promise<VerifiedKyaAuthority>;
}

interface LegacyConstraints extends Record<string, unknown> {
  audience?: string | string[];
  scopes?: string[];
  notBefore?: number;
  notAfter?: number;
  invocationTarget?: string;
  maxAmount?: string;
  currency?: string;
}

function issuerDid(credential: DelegationCredential): string {
  return typeof credential.issuer === "string" ? credential.issuer : credential.issuer.id;
}

function toUpstreamDidResolver(resolver: KyaDidResolver): DIDResolver {
  return {
    resolve: async (did) => {
      const document = await resolver.resolveDidDocument(did);
      const assertionIds = new Set(
        document.assertionMethod.map((entry) => (typeof entry === "string" ? entry : entry.id)),
      );
      return {
        id: document.id,
        verificationMethod: document.verificationMethod
          .filter((method) => assertionIds.has(method.id))
          .map((method) => ({
            id: method.id,
            type: method.type,
            controller: method.controller,
            ...(method.publicKeyJwk === undefined ? {} : { publicKeyJwk: method.publicKeyJwk }),
            ...(method.publicKeyMultibase === undefined
              ? {}
              : { publicKeyMultibase: method.publicKeyMultibase }),
          })),
        assertionMethod: [...assertionIds],
      };
    },
  };
}

async function verifyLegacySignature(
  credential: DelegationCredential,
  publicKeyJwk: unknown,
): Promise<{ valid: boolean; reason?: string }> {
  try {
    const proofValue = credential.proof?.proofValue;
    if (typeof proofValue !== "string" || !/^[A-Za-z0-9_-]+$/u.test(proofValue)) {
      return { valid: false, reason: "Legacy proofValue is not base64url" };
    }
    const unsigned = structuredClone(credential) as Record<string, unknown>;
    delete unsigned.proof;
    const key = createPublicKey({
      key: publicKeyJwk as JsonWebKey,
      format: "jwk",
    });
    return {
      valid: verifyBytes(
        null,
        Buffer.from(canonicalizeJSON(unsigned), "utf8"),
        key,
        Buffer.from(proofValue, "base64url"),
      ),
    };
  } catch {
    return { valid: false, reason: "Legacy credential signature verification failed" };
  }
}

function extractCredential(
  value: KyaLegacyAuthorityPresentation["credential"],
): DelegationCredential {
  if (typeof value === "string") {
    const prepared = prepareVcJwtCredential(value, Date.now());
    if ("failure" in prepared) {
      throw new KyaAuthorityError(
        "KYA_DELEGATION_INVALID",
        "delegation",
        "Legacy VC-JWT is malformed",
      );
    }
    return prepared.vc;
  }
  const parsed = validateDelegationCredential(value);
  if (!parsed.success || parsed.data === undefined) {
    throw new KyaAuthorityError(
      "KYA_DELEGATION_INVALID",
      "delegation",
      "Legacy DelegationCredential is malformed",
    );
  }
  return parsed.data;
}

function exactAudience(constraints: LegacyConstraints, expected: string): boolean {
  return typeof constraints.audience === "string"
    ? constraints.audience === expected
    : Array.isArray(constraints.audience) && constraints.audience.includes(expected);
}

function acceptedDid(did: string, policy: KyaAuthorityPolicyV1): boolean {
  const method = didMethodOf(did);
  return method !== undefined && policy.accepted_did_methods.includes(method);
}

export class UpstreamLegacyKyaVerificationAdapter implements LegacyKyaVerificationAdapter {
  readonly #mapper = new StrictKyaFinancialActionMapper();

  constructor(
    readonly options: {
      resolver: KyaDidResolver;
      requestProof: KyaRequestProofVerifier;
      revocation: RevocationChecker;
    },
  ) {}

  async verify(input: {
    presentation: KyaLegacyAuthorityPresentation;
    action: InntrisActionV1;
    policy: KyaAuthorityPolicyV1;
    expectedAudience: string;
    now: Date;
  }): Promise<VerifiedKyaAuthority> {
    if (input.presentation.proof === undefined) {
      throw new KyaAuthorityError(
        "KYA_PROOF_INVALID",
        "request_proof",
        "Legacy financial authority requires a live request proof",
      );
    }
    if (input.policy.principal_source !== "responsible_party") {
      throw new KyaAuthorityError(
        "KYA_PRINCIPAL_MISMATCH",
        "delegation",
        "Legacy compatibility does not establish an Entity Card principal",
      );
    }
    const proof = await this.options.requestProof.verify({
      proof: input.presentation.proof,
      request: input.presentation.request,
      expectedAudience: input.expectedAudience,
    });
    const financial = this.#mapper.map(input.presentation.request);
    const credential = extractCredential(input.presentation.credential);
    let revocationFresh = false;
    const statusListResolver: StatusListResolver = {
      checkStatus: async (status) => {
        const result = await this.options.revocation({
          statusListCredential: status.statusListCredential,
          statusListIndex: status.statusListIndex,
        });
        revocationFresh = result.fresh;
        if (!result.fresh) throw new Error("Legacy revocation status is stale");
        return result.revoked;
      },
    };
    const verifier = new DelegationCredentialVerifier({
      didResolver: toUpstreamDidResolver(this.options.resolver),
      statusListResolver,
      signatureVerifier: verifyLegacySignature,
      cacheTtl: 1,
    });
    const result =
      typeof input.presentation.credential === "string"
        ? await verifier.verifyDelegationJwt(input.presentation.credential, { skipCache: true })
        : await verifier.verifyDelegationCredential(credential, { skipCache: true });
    if (!result.valid) {
      if (result.statusOutcome === "revoked") {
        throw new KyaAuthorityError(
          "KYA_DELEGATION_REVOKED",
          "revocation",
          "Legacy delegation is revoked",
        );
      }
      if (result.statusOutcome === "status_unresolvable") {
        throw new KyaAuthorityError(
          "KYA_REVOCATION_UNAVAILABLE",
          "revocation",
          "Legacy delegation status could not be verified",
        );
      }
      throw new KyaAuthorityError(
        result.checks?.signatureValid === false
          ? "KYA_DELEGATION_SIGNATURE_INVALID"
          : "KYA_DELEGATION_INVALID",
        result.checks?.signatureValid === false ? "delegation_signature" : "delegation",
        "Legacy delegation verification failed",
      );
    }
    if (input.policy.require_fresh_revocation && !revocationFresh) {
      throw new KyaAuthorityError(
        "KYA_REVOCATION_UNAVAILABLE",
        "revocation",
        "Fresh legacy revocation state is required",
      );
    }
    const delegation = credential.credentialSubject.delegation;
    const constraints = delegation.constraints as LegacyConstraints;
    const responsiblePartyDid = issuerDid(credential);
    if (
      delegation.issuerDid !== responsiblePartyDid ||
      delegation.subjectDid !== credential.credentialSubject.id ||
      delegation.subjectDid !== proof.did
    ) {
      throw new KyaAuthorityError(
        "KYA_AGENT_IDENTITY_MISMATCH",
        "delegation",
        "Legacy delegation identity continuity does not match the live proof",
      );
    }
    if (!exactAudience(constraints, input.expectedAudience)) {
      throw new KyaAuthorityError(
        "KYA_AUDIENCE_MISMATCH",
        "delegation",
        "Legacy delegation audience does not match",
      );
    }
    if (!constraints.scopes?.includes("payments.transfer")) {
      throw new KyaAuthorityError(
        "KYA_ACTION_NOT_DELEGATED",
        "delegation",
        "Legacy delegation does not explicitly designate payments.transfer",
      );
    }
    if (!acceptedDid(proof.did, input.policy) || !acceptedDid(responsiblePartyDid, input.policy)) {
      throw new KyaAuthorityError(
        "KYA_AGENT_IDENTITY_MISMATCH",
        "delegation",
        "Legacy delegation uses an unaccepted DID method",
      );
    }
    if (!input.policy.responsible_parties.includes(responsiblePartyDid)) {
      throw new KyaAuthorityError(
        "KYA_RESPONSIBLE_PARTY_NOT_ALLOWED",
        "delegation",
        "Legacy Responsible Party is not allowlisted",
      );
    }
    if (input.policy.min_proof_assurance === "L3" && proof.assurance !== "L3") {
      throw new KyaAuthorityError(
        "KYA_PROOF_ASSURANCE_INSUFFICIENT",
        "request_proof",
        "Legacy request proof assurance is below policy",
      );
    }
    const maxAmount = KyaAmountSchema.safeParse(constraints.maxAmount);
    if (!maxAmount.success && input.policy.require_max_amount) {
      throw new KyaAuthorityError(
        "KYA_MAX_AMOUNT_REQUIRED",
        "financial_join",
        "Legacy signed constraints require canonical maxAmount",
      );
    }
    if (input.action.agent_id !== proof.did || input.action.principal_id !== responsiblePartyDid) {
      throw new KyaAuthorityError(
        "KYA_PRINCIPAL_MISMATCH",
        "financial_join",
        "Inntris identities do not match legacy delegated authority",
      );
    }
    if (
      input.action.transaction.amount !== financial.amount ||
      input.action.transaction.payee !== financial.payee
    ) {
      throw new KyaAuthorityError(
        "KYA_AUTHORITY_BINDING_MISMATCH",
        "financial_join",
        "Legacy payment request does not match the Inntris transaction",
      );
    }
    const resource = input.policy.resource_bindings.find(
      (binding) => binding.inntris_resource === input.action.protocol_reference.resource,
    );
    if (
      resource?.kya_invocation_target !== financial.resource ||
      constraints.invocationTarget !== financial.resource
    ) {
      throw new KyaAuthorityError(
        "KYA_INVOCATION_TARGET_MISMATCH",
        "financial_join",
        "Legacy invocation target is not exactly mapped",
      );
    }
    const currency = input.policy.currency_bindings.find(
      (binding) => binding.inntris_asset === input.action.transaction.asset,
    );
    if (
      currency?.kya_currency !== financial.currency ||
      constraints.currency !== financial.currency
    ) {
      throw new KyaAuthorityError(
        "KYA_CURRENCY_MISMATCH",
        "financial_join",
        "Legacy currency is not explicitly mapped",
      );
    }
    if (
      maxAmount.success &&
      new Decimal(input.action.transaction.amount).greaterThan(maxAmount.data)
    ) {
      throw new KyaAuthorityError(
        "KYA_AMOUNT_EXCEEDS_DELEGATION",
        "financial_join",
        "Payment exceeds legacy delegated maxAmount",
      );
    }
    const expiries = [proof.expires * 1_000];
    if (credential.expirationDate !== undefined)
      expiries.push(Date.parse(credential.expirationDate));
    if (constraints.notAfter !== undefined) expiries.push(constraints.notAfter * 1_000);
    if (
      (constraints.notBefore !== undefined &&
        input.now.getTime() < constraints.notBefore * 1_000) ||
      expiries.some((expiry) => Number.isNaN(expiry) || input.now.getTime() >= expiry)
    ) {
      throw new KyaAuthorityError(
        "KYA_DELEGATION_EXPIRED",
        "delegation",
        "Legacy delegation is outside its signed validity window",
      );
    }
    const authorityExpiresAt = new Date(Math.min(...expiries));
    const binding = completeVerifiedBinding({
      version: "inntris-kya-authority-binding-v1",
      status: "verified",
      profile: "legacy-v1",
      protocol_version: KYA_PROTOCOL_VERSION,
      reference_implementation: {
        package: KYA_REFERENCE_PACKAGE,
        version: KYA_REFERENCE_PACKAGE_VERSION,
      },
      authority_policy_hash: hashKyaAuthorityPolicy(input.policy),
      presentation_hash: hashCanonical(input.presentation),
      proof_hash: proof.proofHash,
      request_hash: proof.requestHash,
      delegation_chain_hash: hashCanonical(credential),
      entity_card_hash: null,
      agent_did: proof.did,
      responsible_party_did: responsiblePartyDid,
      principal_did: null,
      proof_assurance: proof.assurance,
      invocation_target: financial.resource,
      allowed_action: "payments.transfer",
      max_amount: maxAmount.success ? maxAmount.data : null,
      currency: financial.currency,
      delegation_depth: 1,
      revocation_fresh: revocationFresh,
      signatures_verified: true,
      verified_at: input.now.toISOString(),
      authority_expires_at: authorityExpiresAt.toISOString(),
    });
    return {
      binding,
      agentDid: proof.did,
      responsiblePartyDid,
      action: "payments.transfer",
      ...(maxAmount.success ? { maxAmount: maxAmount.data } : {}),
      currency: financial.currency,
      invocationTarget: financial.resource,
      authorityExpiresAt,
    };
  }
}

export class DisabledLegacyKyaVerificationAdapter implements LegacyKyaVerificationAdapter {
  async verify(): Promise<never> {
    throw new KyaAuthorityError(
      "KYA_PRESENTATION_INVALID",
      "presentation",
      "legacy-v1 verification is not configured",
    );
  }
}
