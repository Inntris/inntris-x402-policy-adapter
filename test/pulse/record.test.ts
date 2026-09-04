import { describe, expect, it } from "vitest";

import {
  PULSE_CASE_COUNT,
  PULSE_RECORD_VERSION,
  createReproductionRecord,
  type ConformanceResult,
} from "../../packages/pulse-conformance-evaluator/src/index.js";

describe("Pulse reproduction record", () => {
  it("creates the strict record metadata and requires unique coverage", () => {
    const results: ConformanceResult[] = Array.from({ length: PULSE_CASE_COUNT }, (_, index) => ({
      id: `independent-${String(index + 1).padStart(2, "0")}`,
      decision: "accept",
      failureCodes: [],
    }));
    const record = createReproductionRecord(results, {
      implementationCommit: "1".repeat(40),
      organization: "Independent Test Organisation",
      publishedUrl: "https://example.test/reproduction.json",
      performedAt: "2030-01-01T00:00:00Z",
    });

    expect(record.recordVersion).toBe(PULSE_RECORD_VERSION);
    expect(record.fixture.caseCount).toBe(80);
    expect(record.implementation.independentOfPrimeBeat).toBe(true);
    expect(() =>
      createReproductionRecord(results.slice(1), {
        implementationCommit: "1".repeat(40),
        organization: "Independent Test Organisation",
        publishedUrl: "https://example.test/reproduction.json",
      }),
    ).toThrow("80 unique case results");
  });
});
