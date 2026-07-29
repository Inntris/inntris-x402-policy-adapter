import { createHash } from "node:crypto";

import { Ed25519SigningProvider } from "./signing.js";

/**
 * Public and intentionally insecure fixture identity.
 * It exists only so tests, examples and committed evidence are reproducible.
 */
export function createPublicDemoSigner(): Ed25519SigningProvider {
  const seed = createHash("sha256")
    .update("inntris-public-demo-key-v1-not-for-production", "utf8")
    .digest();
  return Ed25519SigningProvider.fromSeed("test-key-1", seed);
}
