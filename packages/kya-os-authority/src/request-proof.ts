import { hashCanonical, systemClock, type Clock, type ReasonCode } from "@inntris/decision-core";
import { CardProofMetaSchema, verifyCardProof } from "@kya-os/mcp/card";

import { KyaAuthorityError } from "./errors.js";
import type {
  KyaDidResolver,
  KyaNonceStore,
  KyaRequestProofVerifier,
  VerifiedKyaRequestProof,
  VerifyKyaRequestProofInput,
} from "./types.js";

const REPLAY_RETENTION_SKEW_SECONDS = 6;

function mapProofFailure(reasons: string[]): ReasonCode {
  if (reasons.includes("nonce_replayed")) return "KYA_PROOF_REPLAYED";
  if (reasons.includes("audience_mismatch")) return "KYA_AUDIENCE_MISMATCH";
  if (
    reasons.some((reason) =>
      [
        "kid_did_mismatch",
        "kid_not_in_did_document",
        "did_membership_unverifiable",
        "key_unresolvable",
        "did_keys_unresolvable",
      ].includes(reason),
    )
  ) {
    return "KYA_AGENT_IDENTITY_MISMATCH";
  }
  return "KYA_PROOF_INVALID";
}

export interface UpstreamKyaRequestProofVerifierOptions {
  resolver: KyaDidResolver;
  nonceStore: KyaNonceStore;
  clock?: Clock;
}

export class UpstreamKyaRequestProofVerifier implements KyaRequestProofVerifier {
  readonly #clock: Clock;

  constructor(readonly options: UpstreamKyaRequestProofVerifierOptions) {
    this.#clock = options.clock ?? systemClock;
  }

  async verify(input: VerifyKyaRequestProofInput): Promise<VerifiedKyaRequestProof> {
    const parsed = CardProofMetaSchema.safeParse(input.proof);
    if (!parsed.success) {
      throw new KyaAuthorityError(
        "KYA_PROOF_INVALID",
        "request_proof",
        "Malformed KYA request proof",
        { cause: parsed.error },
      );
    }
    const proof = parsed.data;
    try {
      const result = await verifyCardProof(proof, input.request, {
        expectedAudience: input.expectedAudience,
        ...(input.tokenCnfJkt === undefined ? {} : { tokenCnfJkt: input.tokenCnfJkt }),
        now: () => this.#clock.now().getTime(),
        resolveKey: async (kid) => {
          const method = await this.options.resolver.resolveVerificationMethod(kid);
          if (method.publicKeyJwk === undefined) {
            throw new TypeError("Request proof verification method has no supported JWK");
          }
          return method.publicKeyJwk;
        },
        resolveDidKeys: (did) => this.options.resolver.resolveDidKeys(did),
        consumeNonceIfFresh: async (nonce, did) =>
          (await this.options.nonceStore.consume({
            did,
            nonce,
            consumedAt: this.#clock.now(),
            expiresAt: new Date((proof.expires + REPLAY_RETENTION_SKEW_SECONDS) * 1_000),
          })) === "consumed",
      });
      if (!result.ok || result.did === undefined || result.level === undefined) {
        const reasonCode = mapProofFailure(result.reasons);
        throw new KyaAuthorityError(
          reasonCode,
          "request_proof",
          `KYA request proof rejected: ${result.reasons.join(", ")}`,
        );
      }
      return {
        did: result.did,
        kid: proof.kid,
        assurance: result.level,
        audience: proof.audience,
        requestHash: hashCanonical(input.request),
        nonce: proof.nonce,
        created: proof.created,
        expires: proof.expires,
        proofHash: hashCanonical(proof),
      };
    } catch (error) {
      if (error instanceof KyaAuthorityError) throw error;
      throw new KyaAuthorityError(
        "KYA_PROOF_INVALID",
        "request_proof",
        "KYA request proof verification failed closed",
        { cause: error },
      );
    }
  }
}
