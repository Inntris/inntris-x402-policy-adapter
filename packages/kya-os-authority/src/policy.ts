import { readFile } from "node:fs/promises";

import { hashPolicyObject } from "@inntris/decision-core";
import { parse } from "yaml";

import { KyaAuthorityPolicyV1Schema, type KyaAuthorityPolicyV1 } from "./schemas.js";

export function parseKyaAuthorityPolicyText(source: string): KyaAuthorityPolicyV1 {
  return KyaAuthorityPolicyV1Schema.parse(parse(source) as unknown);
}

export async function loadKyaAuthorityPolicyFile(path: string): Promise<KyaAuthorityPolicyV1> {
  return parseKyaAuthorityPolicyText(await readFile(path, "utf8"));
}

export function hashKyaAuthorityPolicy(policy: KyaAuthorityPolicyV1): string {
  return hashPolicyObject(KyaAuthorityPolicyV1Schema.parse(policy));
}

export function didMethodOf(did: string): "did:key" | "did:web" | undefined {
  if (did.startsWith("did:key:")) return "did:key";
  if (did.startsWith("did:web:")) return "did:web";
  return undefined;
}
