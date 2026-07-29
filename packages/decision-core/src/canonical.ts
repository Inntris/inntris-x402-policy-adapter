import canonicalize from "canonicalize";
import { createHash } from "node:crypto";

import { InntrisActionV1Schema, type InntrisActionV1 } from "./schemas.js";

export function canonicalise(value: unknown): string {
  const result = canonicalize(value);
  if (result === undefined) {
    throw new TypeError("Value cannot be represented by RFC 8785 JCS");
  }
  return result;
}

export function canonicalBytes(value: unknown): Uint8Array {
  return Buffer.from(canonicalise(value), "utf8");
}

export function sha256Bytes(value: Uint8Array): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

export function hashCanonical(value: unknown): string {
  return sha256Bytes(canonicalBytes(value));
}

export function hashAction(input: InntrisActionV1): string {
  const action = InntrisActionV1Schema.parse(input);
  return hashCanonical(action);
}

export function hashPolicyObject(validatedPolicy: unknown): string {
  return hashCanonical(validatedPolicy);
}
