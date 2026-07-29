import type { ReasonCode, Verdict } from "./schemas.js";

export interface MetricsRecorder {
  decision(verdict: Verdict, rail: string, latencyMs: number): void;
  verificationFailure(reason: ReasonCode): void;
  replayAttempt(): void;
}

export class InMemoryMetrics implements MetricsRecorder {
  readonly decisions = new Map<string, number>();
  readonly decisionLatenciesMs: number[] = [];
  readonly verificationFailures = new Map<ReasonCode, number>();
  replayAttempts = 0;

  decision(verdict: Verdict, rail: string, latencyMs: number): void {
    const key = `${verdict}:${rail}`;
    this.decisions.set(key, (this.decisions.get(key) ?? 0) + 1);
    this.decisionLatenciesMs.push(latencyMs);
  }

  verificationFailure(reason: ReasonCode): void {
    this.verificationFailures.set(reason, (this.verificationFailures.get(reason) ?? 0) + 1);
  }

  replayAttempt(): void {
    this.replayAttempts += 1;
  }
}

export const noOpMetrics: MetricsRecorder = {
  decision: () => undefined,
  verificationFailure: () => undefined,
  replayAttempt: () => undefined,
};
