import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";

import {
  blindPinnedFixture,
  calculateInputHash,
  evaluateCase,
  parseBlindedBundleBytes,
  parseConformanceCase,
} from "../../packages/pulse-conformance-evaluator/src/index.js";
import { makeConformanceCase } from "./helpers.js";

describe("Pulse strict parser and blinding boundary", () => {
  it("rejects expected anywhere in evaluator input", () => {
    const raw = Buffer.from(
      JSON.stringify({
        bundleVersion: "ap2-x402-conformance-bundle/0.3",
        cases: [{ ap2: { expected: { decision: "accept" } } }],
      }),
    );

    expect(() => parseBlindedBundleBytes(raw)).toThrow("Evaluator input must not contain expected");
  });

  it("rejects unknown case fields", async () => {
    const fixtureCase = await makeConformanceCase();

    expect(() => parseConformanceCase({ ...fixtureCase, futureField: true })).toThrow();
  });

  it("maps a missing or unknown selected x402 instrument extension to schema failure", async () => {
    const missing = await makeConformanceCase();
    delete missing.ap2.closedMandate.payment_instrument.x402;
    missing.inputHash = calculateInputHash(missing);
    expect(() => parseConformanceCase(missing)).toThrow();
    await expect(
      evaluateCase(missing, {
        verify: async () => {
          throw new Error("the AP2 verifier must not run for invalid input");
        },
      }),
    ).resolves.toEqual({
      id: "independent-test-case",
      decision: "reject",
      failureCodes: ["INPUT_SCHEMA_INVALID"],
    });

    const unknown = await makeConformanceCase();
    const extension = unknown.ap2.closedMandate.payment_instrument.x402;
    if (extension === undefined) throw new Error("Test extension setup failed");
    extension.futureField = true;
    unknown.inputHash = calculateInputHash(unknown);
    expect(() => parseConformanceCase(unknown)).toThrow();
    await expect(
      evaluateCase(unknown, {
        verify: async () => {
          throw new Error("the AP2 verifier must not run for invalid input");
        },
      }),
    ).resolves.toEqual({
      id: "independent-test-case",
      decision: "reject",
      failureCodes: ["INPUT_SCHEMA_INVALID"],
    });
  });

  it("rejects non-canonical encodings and values outside uint256", async () => {
    const nonCanonical = await makeConformanceCase();
    nonCanonical.ap2.closedMandate.transaction_id = `${"A".repeat(42)}B`;
    expect(() => parseConformanceCase(nonCanonical)).toThrow("canonical unpadded base64url");

    const overflow = await makeConformanceCase();
    overflow.x402.requirements.amount = (1n << 256n).toString();
    expect(() => parseConformanceCase(overflow)).toThrow("unsigned 256 bit integer");
  });

  it("rejects raw fixture bytes before blinding when the SHA-256 is wrong", async () => {
    const directory = await mkdtemp(join(tmpdir(), "inntris-pulse-parser-"));
    const source = join(directory, "source.json");
    const output = join(directory, "output.json");
    const target = resolve(directory);
    if (!target.startsWith(resolve(tmpdir()))) throw new Error("Unsafe temporary path");
    try {
      await writeFile(source, "{}\n", "utf8");
      await expect(blindPinnedFixture(source, output)).rejects.toThrow(
        "Raw fixture SHA-256 mismatch",
      );
    } finally {
      await rm(target, { recursive: true, force: true });
    }
  });
});
