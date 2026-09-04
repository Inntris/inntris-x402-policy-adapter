import { canonicalBytes } from "@inntris/decision-core";
import { createHash } from "node:crypto";

import type { ConformanceCase } from "./types.js";

export function sha256Base64Url(value: Uint8Array | string): string {
  return createHash("sha256").update(value).digest("base64url");
}

export function sha256Hex(value: Uint8Array | string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function canonicalHash(value: unknown): string {
  return sha256Base64Url(canonicalBytes(value));
}

export function calculateInputHash(fixtureCase: ConformanceCase): string {
  return canonicalHash({
    caseVersion: fixtureCase.caseVersion,
    sourcePins: fixtureCase.sourcePins,
    nowEpochSeconds: fixtureCase.nowEpochSeconds,
    ap2: fixtureCase.ap2,
    x402: fixtureCase.x402,
  });
}
