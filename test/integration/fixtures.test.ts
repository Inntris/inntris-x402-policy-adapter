import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { promisify } from "node:util";
import { resolve } from "node:path";

import type { InntrisActionV1, InntrisDecisionV1, ReasonCode } from "@inntris/decision-core";
import { verifyDecision } from "@inntris/decision-verifier";
import { describe, expect, it } from "vitest";

interface FixtureExpectation {
  verification_valid: boolean;
  reason_code: ReasonCode | null;
  settlement_may_proceed: boolean;
}

interface DecisionFixture {
  name: string;
  decision: InntrisDecisionV1;
  action: InntrisActionV1;
  expected: FixtureExpectation;
  expected_policy_version?: string;
  expected_payment_requirements_hash?: string;
}

const run = promisify(execFile);

async function jsonFile<T>(path: string): Promise<T> {
  return JSON.parse(await readFile(resolve(path), "utf8")) as T;
}

describe("committed public evidence and test vectors", () => {
  it("matches every committed vector's expected verification result", async () => {
    const manifest = await jsonFile<{ name: string }[]>("fixtures/manifest.json");
    const keyRegistry = await jsonFile<unknown>("fixtures/keys/registry.json");
    expect(manifest).toHaveLength(13);

    for (const entry of manifest) {
      const fixture = await jsonFile<DecisionFixture>(`fixtures/decisions/${entry.name}.json`);
      const result = verifyDecision({
        decision: fixture.decision,
        action: fixture.action,
        keyRegistry,
        at: new Date("2026-07-29T09:30:30.000Z"),
        expectedPolicyVersion: fixture.expected_policy_version,
        expectedPaymentRequirementsHash: fixture.expected_payment_requirements_hash,
      });
      expect(result.valid, fixture.name).toBe(fixture.expected.verification_valid);
      if (
        fixture.expected.reason_code !== null &&
        !["DECISION_NOT_ALLOW", "NONCE_ALREADY_CONSUMED"].includes(fixture.expected.reason_code)
      ) {
        expect(result.reason_codes, fixture.name).toContain(fixture.expected.reason_code);
      }
      if (fixture.expected.settlement_may_proceed) {
        expect(fixture.decision.verdict, fixture.name).toBe("ALLOW");
        expect(result.valid, fixture.name).toBe(true);
      }
    }
  });

  it("verifies the public ALLOW sample with the standalone CLI", async () => {
    const { stdout } = await run(
      process.execPath,
      [
        "packages/decision-verifier/dist/cli.js",
        "decision",
        "evidence/allow.json",
        "--action",
        "evidence/action.json",
        "--keys",
        "fixtures/keys/registry.json",
        "--expected-policy-version",
        "1",
        "--at",
        "2026-07-29T09:30:30.000Z",
      ],
      { cwd: resolve(".") },
    );
    expect(stdout).toContain("PASS Ed25519 signature");
    expect(stdout).toContain("VERDICT: ALLOW");
    expect(stdout).toContain("DECISION: VALID");
  });

  it("returns machine-readable output and a nonzero code for tampering", async () => {
    await expect(
      run(
        process.execPath,
        [
          "packages/decision-verifier/dist/cli.js",
          "decision",
          "evidence/allow.json",
          "--action",
          "fixtures/actions/block.json",
          "--keys",
          "fixtures/keys/registry.json",
          "--at",
          "2026-07-29T09:30:30.000Z",
          "--json",
        ],
        { cwd: resolve(".") },
      ),
    ).rejects.toMatchObject({ code: 1 });
  });
});
