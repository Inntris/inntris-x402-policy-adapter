import type {
  Clock,
  BlockDecisionIssuer,
  BoundApprovalDecisionProvider,
  ConsumeDecisionInput,
  ConsumeDecisionResult,
  DecisionProvider,
  InntrisActionV1,
  InntrisDecisionV1,
  ResolveApprovalInput,
  ResolveApprovalResult,
} from "@inntris/decision-core";
import type { ProofPublicJwk, RevocationChecker } from "@kya-os/mcp/card";

import type {
  KyaAuthorityPolicyV1,
  KyaAuthorityPresentation,
  KyaDecisionAuthorityRecord,
  KyaAuthorityRevalidationRecord,
  KyaToolRequest,
  VerifiedKyaAuthorityBindingV1,
} from "./schemas.js";
import type { KyaMetricsRecorder } from "./metrics.js";

export interface KyaVerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyJwk?: ProofPublicJwk;
  publicKeyMultibase?: string;
}

export interface KyaDidDocument {
  id: string;
  verificationMethod: KyaVerificationMethod[];
  authentication: (string | KyaVerificationMethod)[];
  assertionMethod: (string | KyaVerificationMethod)[];
}

export interface KyaDidResolver {
  resolveDidDocument(did: string): Promise<KyaDidDocument>;
  resolveVerificationMethod(kid: string): Promise<KyaVerificationMethod>;
  resolveDidKeys(did: string): Promise<ProofPublicJwk[]>;
}

export interface KyaNonceStore {
  readonly durability: "memory" | "durable";
  consume(input: {
    did: string;
    nonce: string;
    consumedAt: Date;
    expiresAt: Date;
  }): Promise<"consumed" | "replay">;
  purgeExpired?(at: Date): Promise<number>;
}

export interface VerifyKyaRequestProofInput {
  proof: unknown;
  request: KyaToolRequest;
  expectedAudience: string;
  tokenCnfJkt?: string;
}

export interface VerifiedKyaRequestProof {
  did: string;
  kid: string;
  assurance: "L3" | "L3-minus";
  audience: string;
  requestHash: string;
  nonce: string;
  created: number;
  expires: number;
  proofHash: string;
}

export interface KyaRequestProofVerifier {
  verify(input: VerifyKyaRequestProofInput): Promise<VerifiedKyaRequestProof>;
}

export interface KyaFinancialAction {
  action: "payments.transfer";
  amount: string;
  currency: string;
  payee: string;
  resource: string;
}

export interface KyaFinancialActionMapper {
  map(request: KyaToolRequest): KyaFinancialAction;
}

export interface KyaDelegationSignatureVerifier {
  verifyCredential(credential: unknown): Promise<void>;
}

export interface VerifiedKyaDelegation {
  agentDid: string;
  responsiblePartyDid: string;
  principalDid?: string;
  invocationTarget: string;
  allowedActions: string[];
  maxAmount?: string;
  currency?: string;
  authorityExpiresAt: Date;
  delegationDepth: number;
  revocationFresh: boolean;
  chainHash: string;
  entityCardHash?: string;
}

export interface KyaDelegationVerifier {
  verify(input: {
    presentation: KyaAuthorityPresentation;
    proof: VerifiedKyaRequestProof;
    policy: KyaAuthorityPolicyV1;
    now: Date;
  }): Promise<VerifiedKyaDelegation>;
}

export interface VerifiedKyaAuthority {
  binding: VerifiedKyaAuthorityBindingV1;
  agentDid: string;
  responsiblePartyDid: string;
  principalDid?: string;
  action: "payments.transfer";
  maxAmount?: string;
  currency?: string;
  invocationTarget: string;
  authorityExpiresAt: Date;
}

export interface VerifyKyaAuthorityInput {
  presentation: KyaAuthorityPresentation;
  action: InntrisActionV1;
  authorityPolicy: KyaAuthorityPolicyV1;
  expectedAudience: string;
  now?: Date;
}

export interface KyaAuthorityVerifier {
  verify(input: VerifyKyaAuthorityInput): Promise<VerifiedKyaAuthority>;
}

export interface KyaAuthorityStateStore {
  readonly durability: "memory" | "durable";
  saveDecisionAuthority(record: KyaDecisionAuthorityRecord): Promise<void>;
  getDecisionAuthority(decisionId: string): Promise<KyaDecisionAuthorityRecord | undefined>;
  appendRevalidation(record: KyaAuthorityRevalidationRecord): Promise<void>;
  getSuccessfulExecutionRevalidation(input: {
    decisionId: string;
    actionHash: string;
    executionRef: string;
  }): Promise<KyaAuthorityRevalidationRecord | undefined>;
}

export interface KyaEvaluateInput {
  action: InntrisActionV1;
  presentation?: KyaAuthorityPresentation;
}

export interface KyaResolveApprovalInput {
  approval: ResolveApprovalInput;
  presentation: KyaAuthorityPresentation;
}

export interface KyaConsumeInput {
  consumption: ConsumeDecisionInput;
  presentation: KyaAuthorityPresentation;
}

export interface KyaAuthorityGateOptions {
  provider: DecisionProvider & BlockDecisionIssuer & BoundApprovalDecisionProvider;
  verifier: KyaAuthorityVerifier;
  authorityPolicy: KyaAuthorityPolicyV1;
  stateStore: KyaAuthorityStateStore;
  mapper?: KyaFinancialActionMapper;
  clock?: Clock;
  metrics?: KyaMetricsRecorder;
}

export interface KyaGate {
  evaluate(input: KyaEvaluateInput): Promise<InntrisDecisionV1>;
  resolveApproval(input: KyaResolveApprovalInput): Promise<ResolveApprovalResult>;
  consume(input: KyaConsumeInput): Promise<ConsumeDecisionResult>;
  protectsDecision(decisionId: string): Promise<boolean>;
}

export interface KyaDelegationVerifierOptions {
  signatures: KyaDelegationSignatureVerifier;
  revocation: RevocationChecker;
}
