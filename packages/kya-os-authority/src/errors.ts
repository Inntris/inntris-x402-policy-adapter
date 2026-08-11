import type { ReasonCode } from "@inntris/decision-core";

export type KyaFailureStage =
  | "presentation"
  | "request_proof"
  | "delegation_signature"
  | "delegation"
  | "revocation"
  | "financial_join"
  | "state";

export class KyaAuthorityError extends Error {
  constructor(
    readonly reasonCode: ReasonCode,
    readonly failureStage: KyaFailureStage,
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "KyaAuthorityError";
  }
}

export function asKyaAuthorityError(error: unknown): KyaAuthorityError {
  if (error instanceof KyaAuthorityError) return error;
  return new KyaAuthorityError(
    "KYA_PRESENTATION_INVALID",
    "presentation",
    "KYA presentation verification failed",
    { cause: error },
  );
}
