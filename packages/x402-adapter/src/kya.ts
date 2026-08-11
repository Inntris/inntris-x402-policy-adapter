import {
  KYA_AUTHORITY_EXTENSION_KEY,
  type KyaAuthorityPolicyV1,
  type KyaAuthorityPresentation,
} from "@inntris/kya-os-authority";
import {
  CardProofMetaSchema,
  DelegationCredentialSchema,
  EntityCardSchema,
  issuerDid,
} from "@kya-os/mcp/card";
import type { PaymentPayload, PaymentRequirements } from "@x402/core/types";

import { actionFromX402 } from "./binding.js";

export interface KyaX402BindingInput {
  paymentRequirements: PaymentRequirements;
  paymentPayload?: PaymentPayload;
  resource: string;
  purpose: string;
  assetDecimals: number;
  presentation: KyaAuthorityPresentation;
  extensions?: Record<string, unknown>;
}

/** Builds only a provisional action identity. The KYA gate must recompute and
 * verify both values before the action reaches organisational policy. */
export function actionFromKyaX402(
  input: KyaX402BindingInput,
  policy: KyaAuthorityPolicyV1,
): ReturnType<typeof actionFromX402> {
  if (input.extensions?.[KYA_AUTHORITY_EXTENSION_KEY] !== undefined) {
    throw new TypeError("The reserved Inntris KYA extension cannot be supplied by a caller");
  }
  if (input.presentation.profile !== "entity-card-v1") {
    throw new TypeError("The x402 reference path requires entity-card-v1");
  }
  const proof = CardProofMetaSchema.parse(input.presentation.request_proof);
  const root = DelegationCredentialSchema.parse(input.presentation.delegation_chain[0]);
  const responsibleParty = issuerDid(root);
  const principal =
    policy.principal_source === "responsible_party"
      ? responsibleParty
      : EntityCardSchema.parse(input.presentation.entity_card).principal;
  if (principal === undefined) {
    throw new TypeError("A verified Entity Card principal is required by KYA policy");
  }
  return actionFromX402({
    paymentRequirements: input.paymentRequirements,
    ...(input.paymentPayload === undefined ? {} : { paymentPayload: input.paymentPayload }),
    resource: input.resource,
    principalId: principal,
    agentId: proof.did,
    purpose: input.purpose,
    assetDecimals: input.assetDecimals,
    ...(input.extensions === undefined ? {} : { extensions: input.extensions }),
  });
}
