import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { randomBytes } from "node:crypto";

import {
  Ed25519SigningProvider,
  buildKeyRegistryEntry,
  publicKeyFingerprint,
} from "@inntris/decision-core";

const seedPath = resolve(process.argv[2] ?? ".dev/decision-signing.seed");
const registryPath = resolve(process.argv[3] ?? ".dev/inntris-keys.json");
const keyId = process.env.INNTRIS_SIGNING_KEY_ID ?? "dev-key-1";

// Generate the seed once and never print it.
const actualSeed = randomBytes(32);
const actualSigner = Ed25519SigningProvider.fromSeed(keyId, actualSeed);
await mkdir(dirname(seedPath), { recursive: true });
await mkdir(dirname(registryPath), { recursive: true });
await writeFile(seedPath, `${actualSeed.toString("base64url")}\n`, {
  encoding: "utf8",
  flag: "wx",
  mode: 0o600,
});
const registry = {
  version: "inntris-key-registry-v1" as const,
  keys: [
    buildKeyRegistryEntry(actualSigner, {
      notBefore: new Date(),
    }),
  ],
};
await writeFile(registryPath, `${JSON.stringify(registry, null, 2)}\n`, {
  encoding: "utf8",
  flag: "wx",
  mode: 0o644,
});

process.stdout.write(
  [
    `Development seed written to ${seedPath}`,
    `Public registry written to ${registryPath}`,
    `Key ID: ${actualSigner.keyId}`,
    `Public key: ${Buffer.from(actualSigner.publicKey).toString("base64url")}`,
    `Fingerprint: ${publicKeyFingerprint(actualSigner.publicKey)}`,
    "The private seed was not printed. This development key is not suitable for production.",
    "",
  ].join("\n"),
);
