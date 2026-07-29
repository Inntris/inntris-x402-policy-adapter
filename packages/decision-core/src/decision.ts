import { randomUUID } from "node:crypto";

import { hashAction } from "./canonical.js";
import {
  InntrisActionV1Schema,
  type Approval,
  type InntrisActionV1,
  type InntrisDecisionV1,
  type ReasonCode,
  type Verdict,
} from "./schemas.js";
import { attachDecisionSignature, randomNonce, type SigningProvider } from "./signing.js";

export interface Clock {
  now(): Date;
}

export const systemClock: Clock = {
  now: () => new Date(),
};

export interface UnsignedEvaluation {
  verdict: Verdict;
  reasonCodes: ReasonCode[];
  approval: Approval;
}

export interface CreateDecisionInput {
  action: InntrisActionV1;
  evaluation: UnsignedEvaluation;
  policyHash: string;
  policyVersion: string;
  decisionTtlSeconds: number;
  signer: SigningProvider;
  clock?: Clock;
  decisionId?: string;
  nonce?: string;
  supersedesDecisionId?: string | null;
}

export async function createSignedDecision(input: CreateDecisionInput): Promise<InntrisDecisionV1> {
  const action = InntrisActionV1Schema.parse(input.action);
  const clock = input.clock ?? systemClock;
  const issuedAt = clock.now();
  const expiresAt = new Date(issuedAt.getTime() + input.decisionTtlSeconds * 1_000);

  return attachDecisionSignature(
    {
      version: "inntris-decision-v1",
      decision_id: input.decisionId ?? randomUUID(),
      verdict: input.evaluation.verdict,
      principal_id: action.principal_id,
      agent_id: action.agent_id,
      action_type: action.action_type,
      action_hash: hashAction(action),
      rail: action.rail,
      protocol_reference: action.protocol_reference,
      transaction: action.transaction,
      policy: {
        policy_hash: input.policyHash,
        policy_version: input.policyVersion,
      },
      approval: input.evaluation.approval,
      reason_codes: input.evaluation.reasonCodes,
      issued_at: issuedAt.toISOString(),
      expires_at: expiresAt.toISOString(),
      nonce: input.nonce ?? randomNonce(),
      supersedes_decision_id: input.supersedesDecisionId ?? null,
      signing: {
        alg: input.signer.algorithm,
        key_id: input.signer.keyId,
      },
    },
    input.signer,
  );
}
