import { canonicalBytes } from "@inntris/decision-core";
import { getAddress, type Address } from "viem";

export function canonicalEqual(left: unknown, right: unknown): boolean {
  try {
    return Buffer.from(canonicalBytes(left)).equals(Buffer.from(canonicalBytes(right)));
  } catch {
    return false;
  }
}

export function normaliseAddress(value: string): Address | undefined {
  try {
    return getAddress(value);
  } catch {
    return undefined;
  }
}

export function addressesEqual(left: string, right: string): boolean {
  const normalisedLeft = normaliseAddress(left);
  const normalisedRight = normaliseAddress(right);
  return normalisedLeft !== undefined && normalisedLeft === normalisedRight;
}

export function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

export function isHex32(value: string): boolean {
  return /^0x[0-9a-fA-F]{64}$/u.test(value);
}
