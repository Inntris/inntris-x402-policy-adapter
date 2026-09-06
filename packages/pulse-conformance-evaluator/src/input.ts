import { readFile, writeFile } from "node:fs/promises";

import { PULSE_FIXTURE_SHA256 } from "./constants.js";
import { sha256Hex } from "./hashing.js";
import { parseConformanceBundle } from "./schemas.js";
import { assertJsonValue, parseStrictJson } from "./strict-json.js";
import type { ConformanceBundle } from "./types.js";

const MAX_INPUT_BYTES = 16_000_000;

function parseJsonBytes(raw: Uint8Array): unknown {
  if (raw.byteLength === 0 || raw.byteLength > MAX_INPUT_BYTES) {
    throw new TypeError("Input size is outside the accepted range");
  }
  const text = new TextDecoder("utf-8", { fatal: true }).decode(raw);
  return parseStrictJson(text);
}

export function parseBlindedBundleBytes(raw: Uint8Array): ConformanceBundle {
  return parseConformanceBundle(parseJsonBytes(raw));
}

export async function readBlindedBundle(path: string): Promise<ConformanceBundle> {
  return parseBlindedBundleBytes(await readFile(path));
}

export async function blindPinnedFixture(sourcePath: string, outputPath: string): Promise<void> {
  const raw = await readFile(sourcePath);
  const actualHash = sha256Hex(raw);
  if (actualHash !== PULSE_FIXTURE_SHA256) {
    throw new TypeError(
      `Raw fixture SHA-256 mismatch: expected ${PULSE_FIXTURE_SHA256}, received ${actualHash}`,
    );
  }
  if (raw.byteLength === 0 || raw.byteLength > MAX_INPUT_BYTES) {
    throw new TypeError("Fixture size is outside the accepted range");
  }
  const text = new TextDecoder("utf-8", { fatal: true }).decode(raw);
  // Only this hash-pinned blinding boundary may temporarily contain expected.
  const value = parseStrictJson(text, false);
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("Fixture bundle must be an object");
  }
  const cases: unknown = "cases" in value ? value.cases : undefined;
  if (!Array.isArray(cases)) throw new TypeError("Fixture cases must be an array");
  for (const fixtureCase of cases as unknown[]) {
    if (fixtureCase === null || typeof fixtureCase !== "object" || Array.isArray(fixtureCase)) {
      throw new TypeError("Fixture case must be an object");
    }
    const caseRecord = fixtureCase as Record<string, unknown>;
    if (!Object.hasOwn(caseRecord, "expected")) {
      throw new TypeError("Source fixture case is already missing expected");
    }
    delete caseRecord.expected;
  }
  assertJsonValue(value);
  parseConformanceBundle(value);
  await writeFile(outputPath, `${JSON.stringify(value, null, 2)}\n`, {
    encoding: "utf8",
    flag: "wx",
  });
}
