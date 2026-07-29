import { InMemoryMetrics } from "@inntris/decision-core";
import { describe, expect, it } from "vitest";

describe("metrics abstraction", () => {
  it("records decision, verification and replay counters without payment data", () => {
    const metrics = new InMemoryMetrics();
    metrics.decision("ALLOW", "x402", 4.2);
    metrics.verificationFailure("INVALID_SIGNATURE");
    metrics.replayAttempt();
    expect(metrics.decisions.get("ALLOW:x402")).toBe(1);
    expect(metrics.decisionLatenciesMs).toEqual([4.2]);
    expect(metrics.verificationFailures.get("INVALID_SIGNATURE")).toBe(1);
    expect(metrics.replayAttempts).toBe(1);
  });
});
