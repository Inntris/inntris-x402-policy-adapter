import type { KyaFailureStage } from "./errors.js";

export interface KyaMetricsRecorder {
  verification(result: "verified" | "rejected", stage: KyaFailureStage | "complete"): void;
  proofReplay(): void;
  delegationRejection(reason: string): void;
  revocationFailure(reason: string): void;
  authorityGate(verdict: "ALLOW" | "BLOCK" | "REQUIRE_APPROVAL"): void;
  revalidation(kind: "approval" | "consumption", result: "verified" | "rejected"): void;
}

export class InMemoryKyaMetrics implements KyaMetricsRecorder {
  readonly verifications = new Map<string, number>();
  readonly delegationRejections = new Map<string, number>();
  readonly revocationFailures = new Map<string, number>();
  readonly authorityGates = new Map<string, number>();
  readonly revalidations = new Map<string, number>();
  proofReplays = 0;

  verification(result: "verified" | "rejected", stage: KyaFailureStage | "complete"): void {
    const key = `${result}:${stage}`;
    this.verifications.set(key, (this.verifications.get(key) ?? 0) + 1);
  }

  proofReplay(): void {
    this.proofReplays += 1;
  }

  delegationRejection(reason: string): void {
    this.delegationRejections.set(reason, (this.delegationRejections.get(reason) ?? 0) + 1);
  }

  revocationFailure(reason: string): void {
    this.revocationFailures.set(reason, (this.revocationFailures.get(reason) ?? 0) + 1);
  }

  authorityGate(verdict: "ALLOW" | "BLOCK" | "REQUIRE_APPROVAL"): void {
    this.authorityGates.set(verdict, (this.authorityGates.get(verdict) ?? 0) + 1);
  }

  revalidation(kind: "approval" | "consumption", result: "verified" | "rejected"): void {
    const key = `${kind}:${result}`;
    this.revalidations.set(key, (this.revalidations.get(key) ?? 0) + 1);
  }
}

export const noOpKyaMetrics: KyaMetricsRecorder = {
  verification: () => undefined,
  proofReplay: () => undefined,
  delegationRejection: () => undefined,
  revocationFailure: () => undefined,
  authorityGate: () => undefined,
  revalidation: () => undefined,
};
