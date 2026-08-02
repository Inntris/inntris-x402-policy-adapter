import { randomBytes } from "node:crypto";

import nacl from "tweetnacl";

import { canonicalBytes, sha256Bytes } from "./canonical.js";
import {
  Base64UrlSchema,
  HashSchema,
  InntrisDecisionV1Schema,
  KeyRegistryEntrySchema,
  type InntrisDecisionV1,
  type KeyRegistryEntry,
} from "./schemas.js";

export interface SigningProvider {
  readonly algorithm: "Ed25519";
  readonly keyId: string;
  readonly publicKey: Uint8Array;
  sign(payload: Uint8Array): Promise<string>;
}

export class Ed25519SigningProvider implements SigningProvider {
  readonly algorithm = "Ed25519" as const;
  readonly publicKey: Uint8Array;
  readonly #secretKey: Uint8Array;

  private constructor(
    readonly keyId: string,
    publicKey: Uint8Array,
    secretKey: Uint8Array,
  ) {
    this.publicKey = publicKey;
    this.#secretKey = secretKey;
  }

  static fromSeed(keyId: string, seed: Uint8Array): Ed25519SigningProvider {
    if (seed.byteLength !== nacl.sign.seedLength) {
      throw new TypeError(`Ed25519 seed must be ${nacl.sign.seedLength} bytes`);
    }
    const pair = nacl.sign.keyPair.fromSeed(seed);
    return new Ed25519SigningProvider(keyId, pair.publicKey, pair.secretKey);
  }

  static fromBase64UrlSeed(keyId: string, encodedSeed: string): Ed25519SigningProvider {
    Base64UrlSchema.parse(encodedSeed);
    return Ed25519SigningProvider.fromSeed(keyId, Buffer.from(encodedSeed, "base64url"));
  }

  async sign(payload: Uint8Array): Promise<string> {
    return Buffer.from(nacl.sign.detached(payload, this.#secretKey)).toString("base64url");
  }
}

type DecisionForFingerprint = Omit<InntrisDecisionV1, "decision_fingerprint" | "signing"> & {
  signing: Omit<InntrisDecisionV1["signing"], "signature">;
};

type SignableDecision = Omit<InntrisDecisionV1, "signing"> & {
  signing: Omit<InntrisDecisionV1["signing"], "signature">;
};

export function decisionFingerprintPayload(
  decision: InntrisDecisionV1 | SignableDecision,
): DecisionForFingerprint {
  const { decision_fingerprint: ignoredFingerprint, signing, ...body } = decision;
  void ignoredFingerprint;
  const { signature: ignoredSignature, ...signingIdentity } =
    "signature" in signing ? signing : { ...signing, signature: undefined };
  void ignoredSignature;
  return {
    ...body,
    signing: signingIdentity,
  };
}

export function signableDecisionPayload(decision: InntrisDecisionV1): SignableDecision {
  const { signature: ignoredSignature, ...signing } = decision.signing;
  void ignoredSignature;
  return {
    ...decision,
    signing,
  };
}

export function calculateDecisionFingerprint(
  decision: InntrisDecisionV1 | SignableDecision,
): string {
  return sha256Bytes(canonicalBytes(decisionFingerprintPayload(decision)));
}

export async function attachDecisionSignature(
  unsigned: Omit<SignableDecision, "decision_fingerprint">,
  signer: SigningProvider,
): Promise<InntrisDecisionV1> {
  if (unsigned.signing.alg !== signer.algorithm || unsigned.signing.key_id !== signer.keyId) {
    throw new TypeError("Signing identity does not match the selected signing provider");
  }

  const fingerprint = calculateDecisionFingerprint({
    ...unsigned,
    decision_fingerprint: HashSchema.parse(
      "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    ),
  });
  const signable: SignableDecision = {
    ...unsigned,
    decision_fingerprint: fingerprint,
  };
  const signature = await signer.sign(canonicalBytes(signable));
  return InntrisDecisionV1Schema.parse({
    ...signable,
    signing: {
      ...signable.signing,
      signature,
    },
  });
}

export function verifyDecisionSignature(
  decision: InntrisDecisionV1,
  publicKey: Uint8Array,
): boolean {
  return verifyEd25519Signature(
    canonicalBytes(signableDecisionPayload(decision)),
    decision.signing.signature,
    publicKey,
  );
}

export function verifyEd25519Signature(
  payload: Uint8Array,
  signatureBase64Url: string,
  publicKey: Uint8Array,
): boolean {
  if (publicKey.byteLength !== nacl.sign.publicKeyLength) {
    return false;
  }
  try {
    const signature = Buffer.from(signatureBase64Url, "base64url");
    return (
      signature.byteLength === nacl.sign.signatureLength &&
      nacl.sign.detached.verify(payload, signature, publicKey)
    );
  } catch {
    return false;
  }
}

export function publicKeyFingerprint(publicKey: Uint8Array): string {
  return sha256Bytes(publicKey);
}

export function buildKeyRegistryEntry(
  signer: SigningProvider,
  options: {
    notBefore: Date;
    notAfter?: Date | null;
    status?: KeyRegistryEntry["status"];
  },
): KeyRegistryEntry {
  return KeyRegistryEntrySchema.parse({
    key_id: signer.keyId,
    alg: signer.algorithm,
    public_key: Buffer.from(signer.publicKey).toString("base64url"),
    fingerprint: publicKeyFingerprint(signer.publicKey),
    status: options.status ?? "active",
    not_before: options.notBefore.toISOString(),
    not_after: options.notAfter?.toISOString() ?? null,
  });
}

export function randomNonce(bytes = 24): string {
  return randomBytes(bytes).toString("base64url");
}
