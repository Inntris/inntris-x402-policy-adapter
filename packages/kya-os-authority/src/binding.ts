import { InntrisActionV1Schema, hashCanonical, type InntrisActionV1 } from "@inntris/decision-core";

import { KyaAuthorityError, type KyaFailureStage } from "./errors.js";
import {
  KYA_AUTHORITY_EXTENSION_KEY,
  KyaAuthorityBindingV1Schema,
  RejectedKyaAuthorityBindingV1Schema,
  VerifiedKyaAuthorityBindingV1Schema,
  type KyaAuthorityPolicyV1,
  type KyaAuthorityPresentation,
  type RejectedKyaAuthorityBindingV1,
  type VerifiedKyaAuthorityBindingV1,
} from "./schemas.js";
import { hashKyaAuthorityPolicy } from "./policy.js";

export function assertNoReservedKyaExtension(action: InntrisActionV1): void {
  if (action.extensions?.[KYA_AUTHORITY_EXTENSION_KEY] !== undefined) {
    throw new KyaAuthorityError(
      "KYA_AUTHORITY_BINDING_MISMATCH",
      "financial_join",
      "Caller supplied the reserved Inntris KYA authority extension",
    );
  }
}

export function withoutKyaExtension(action: InntrisActionV1): InntrisActionV1 {
  if (action.extensions?.[KYA_AUTHORITY_EXTENSION_KEY] === undefined) return action;
  const extensions = Object.fromEntries(
    Object.entries(action.extensions).filter(([key]) => key !== KYA_AUTHORITY_EXTENSION_KEY),
  );
  const withoutExtensions = { ...action };
  delete withoutExtensions.extensions;
  return InntrisActionV1Schema.parse({
    ...withoutExtensions,
    ...(Object.keys(extensions).length === 0 ? {} : { extensions }),
  });
}

export function attachKyaAuthorityBinding(
  action: InntrisActionV1,
  binding: VerifiedKyaAuthorityBindingV1 | RejectedKyaAuthorityBindingV1,
): InntrisActionV1 {
  const clean = withoutKyaExtension(action);
  const parsedBinding = KyaAuthorityBindingV1Schema.parse(binding);
  return InntrisActionV1Schema.parse({
    ...clean,
    extensions: {
      ...clean.extensions,
      [KYA_AUTHORITY_EXTENSION_KEY]: parsedBinding,
    },
  });
}

export function completeVerifiedBinding(
  binding: Omit<VerifiedKyaAuthorityBindingV1, "authority_hash">,
): VerifiedKyaAuthorityBindingV1 {
  const authorityHash = hashCanonical(binding);
  return VerifiedKyaAuthorityBindingV1Schema.parse({
    ...binding,
    authority_hash: authorityHash,
  });
}

export function createRejectedKyaBinding(input: {
  policy: KyaAuthorityPolicyV1;
  presentation: KyaAuthorityPresentation;
  failureStage: KyaFailureStage;
}): RejectedKyaAuthorityBindingV1 {
  return RejectedKyaAuthorityBindingV1Schema.parse({
    version: "inntris-kya-authority-binding-v1",
    status: "rejected",
    profile: input.presentation.profile,
    authority_policy_hash: hashKyaAuthorityPolicy(input.policy),
    presentation_hash: hashCanonical(input.presentation),
    failure_stage: input.failureStage,
  });
}
