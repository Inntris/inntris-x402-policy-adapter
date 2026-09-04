import { arch, platform, release } from "node:os";

import {
  AP2_COMMIT,
  PULSE_CASE_COUNT,
  PULSE_FIXTURE_COMMIT,
  PULSE_FIXTURE_PATH,
  PULSE_FIXTURE_SHA256,
  PULSE_RECORD_VERSION,
  X402_PACKAGE_VERSION,
} from "./constants.js";
import type { ConformanceResult, ReproductionRecord } from "./types.js";

export interface ReproductionRecordOptions {
  implementationCommit: string;
  organization: string;
  publishedUrl: string;
  performedAt?: string;
  repositoryUrl?: string;
  command?: string;
  notes?: string;
}

function requireUrl(value: string, label: string): string {
  const parsed = new URL(value);
  if (parsed.protocol !== "https:") throw new TypeError(`${label} must use HTTPS`);
  return value;
}

export function createReproductionRecord(
  results: ConformanceResult[],
  options: ReproductionRecordOptions,
): ReproductionRecord {
  if (!/^[0-9a-f]{40}$/u.test(options.implementationCommit)) {
    throw new TypeError("implementationCommit must be a full lowercase Git SHA");
  }
  if (options.organization.trim() === "") throw new TypeError("organization is required");
  if (
    results.length !== PULSE_CASE_COUNT ||
    new Set(results.map((result) => result.id)).size !== PULSE_CASE_COUNT
  ) {
    throw new TypeError("The record must contain 80 unique case results");
  }
  for (const result of results) {
    if ((result.decision === "accept") !== (result.failureCodes.length === 0)) {
      throw new TypeError(`Decision and failure codes disagree for ${result.id}`);
    }
  }
  const performedAt = options.performedAt ?? new Date().toISOString();
  if (Number.isNaN(Date.parse(performedAt)))
    throw new TypeError("performedAt must be an ISO timestamp");
  return {
    recordVersion: PULSE_RECORD_VERSION,
    performedAt,
    implementation: {
      repositoryUrl: requireUrl(
        options.repositoryUrl ?? "https://github.com/Inntris/inntris-x402-policy-adapter",
        "repositoryUrl",
      ),
      commit: options.implementationCommit,
      language: "TypeScript and Python",
      runtime: `Node.js ${process.version}; Python 3.12`,
      command:
        options.command ??
        "pnpm pulse:evaluate -- --input evaluator-input.json --record reproduction.json",
      organization: options.organization,
      independentOfPrimeBeat: true,
    },
    fixture: {
      repositoryCommit: PULSE_FIXTURE_COMMIT,
      path: PULSE_FIXTURE_PATH,
      sha256: PULSE_FIXTURE_SHA256,
      caseCount: PULSE_CASE_COUNT,
    },
    environment: {
      operatingSystem: `${platform()} ${release()}`,
      architecture: arch(),
      dependencies: [
        `@x402/core ${X402_PACKAGE_VERSION}`,
        `@x402/evm ${X402_PACKAGE_VERSION}`,
        "canonicalize 3.0.0",
        "viem 2.55.8",
        "zod 4.4.3",
        `google-agentic-commerce/AP2 ${AP2_COMMIT}`,
        "cryptography 50.0.0",
        "jwcrypto 1.5.7",
      ],
    },
    results,
    notes: options.notes ?? "Offline synthetic fixture evaluation only; no live settlement claim.",
    publishedUrl: requireUrl(options.publishedUrl, "publishedUrl"),
  };
}
