import { readFile } from "node:fs/promises";

import {
  KeyRegistrySchema,
  publicKeyFingerprint,
  type KeyRegistry,
  type SigningProvider,
} from "@inntris/decision-core";

export async function loadKeyRegistryFile(path: string): Promise<KeyRegistry> {
  return KeyRegistrySchema.parse(JSON.parse(await readFile(path, "utf8")) as unknown);
}

export function assertSigningProviderRegistered(
  signer: SigningProvider,
  registryInput: unknown,
  at: Date = new Date(),
): KeyRegistry {
  const registry = KeyRegistrySchema.parse(registryInput);
  const entry = registry.keys.find((key) => key.key_id === signer.keyId);
  if (entry?.status !== "active" || entry.alg !== signer.algorithm) {
    throw new Error("Configured signing provider is not an active registry key");
  }
  const time = at.getTime();
  if (
    time < Date.parse(entry.not_before) ||
    (entry.not_after !== null && time >= Date.parse(entry.not_after))
  ) {
    throw new Error("Configured signing provider is outside its registry validity window");
  }
  if (
    entry.public_key !== Buffer.from(signer.publicKey).toString("base64url") ||
    entry.fingerprint !== publicKeyFingerprint(signer.publicKey)
  ) {
    throw new Error("Configured signing provider does not match its registry public key");
  }
  return registry;
}

export function assertRotationRegistry(registryInput: unknown): KeyRegistry {
  const registry = KeyRegistrySchema.parse(registryInput);
  if (!registry.keys.some((key) => key.status === "active")) {
    throw new Error("Key rotation registry must contain at least one active key");
  }
  for (const key of registry.keys) {
    if (key.status === "retired" && key.not_after === null) {
      throw new Error(`Retired key ${key.key_id} requires not_after`);
    }
    if (key.not_after !== null && Date.parse(key.not_after) <= Date.parse(key.not_before)) {
      throw new Error(`Key ${key.key_id} requires not_after later than not_before`);
    }
  }
  return registry;
}
