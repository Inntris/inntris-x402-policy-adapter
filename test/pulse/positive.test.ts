import { describe, expect, it } from "vitest";

import { evaluateCase } from "../../packages/pulse-conformance-evaluator/src/index.js";
import { makeConformanceCase, makeMockVerifier } from "./helpers.js";

describe("Pulse evaluator positive path", () => {
  it("accepts a fully bound independently generated case", async () => {
    const fixtureCase = await makeConformanceCase();
    const result = await evaluateCase(fixtureCase, makeMockVerifier(fixtureCase));

    expect(result).toEqual({
      id: "independent-test-case",
      decision: "accept",
      failureCodes: [],
    });
  });
});
