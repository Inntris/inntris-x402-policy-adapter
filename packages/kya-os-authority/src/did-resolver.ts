import {
  ProofPublicJwkSchema,
  createSafeFetch,
  type ProofPublicJwk,
  type SafeFetch,
} from "@kya-os/mcp/card";
import { resolveDidKeySync } from "@kya-os/mcp/delegation";

import { KyaAuthorityError } from "./errors.js";
import type { KyaDidDocument, KyaDidResolver, KyaVerificationMethod } from "./types.js";

interface DidDocumentInput {
  id?: unknown;
  verificationMethod?: unknown;
  authentication?: unknown;
  assertionMethod?: unknown;
}

function parseMethod(value: unknown, expectedDid: string): KyaVerificationMethod {
  if (typeof value !== "object" || value === null) {
    throw new TypeError("DID verification method must be an object");
  }
  const method = value as Record<string, unknown>;
  if (
    typeof method.id !== "string" ||
    typeof method.type !== "string" ||
    method.controller !== expectedDid ||
    !method.id.startsWith(`${expectedDid}#`)
  ) {
    throw new TypeError("DID verification method is not controlled by the expected DID");
  }
  const parsedJwk =
    method.publicKeyJwk === undefined
      ? undefined
      : ProofPublicJwkSchema.parse({
          ...(method.publicKeyJwk as Record<string, unknown>),
          kid: method.id,
        });
  if (parsedJwk === undefined && typeof method.publicKeyMultibase !== "string") {
    throw new TypeError("DID verification method has no supported public key");
  }
  return {
    id: method.id,
    type: method.type,
    controller: expectedDid,
    ...(parsedJwk === undefined ? {} : { publicKeyJwk: parsedJwk }),
    ...(typeof method.publicKeyMultibase === "string"
      ? { publicKeyMultibase: method.publicKeyMultibase }
      : {}),
  };
}

function purposeEntries(
  entries: unknown,
  methods: Map<string, KyaVerificationMethod>,
): (string | KyaVerificationMethod)[] {
  if (!Array.isArray(entries)) return [];
  return entries.map((entry) => {
    if (typeof entry === "string") return entry;
    const id =
      typeof entry === "object" && entry !== null
        ? (entry as Record<string, unknown>).id
        : undefined;
    if (typeof id !== "string") throw new TypeError("Invalid DID relationship entry");
    const method = methods.get(id);
    if (method === undefined) throw new TypeError("Embedded DID relationship key is not published");
    return method;
  });
}

function parseDidDocument(value: unknown, expectedDid: string): KyaDidDocument {
  if (typeof value !== "object" || value === null) {
    throw new TypeError("DID document must be an object");
  }
  const document = value as DidDocumentInput;
  if (document.id !== expectedDid || !Array.isArray(document.verificationMethod)) {
    throw new TypeError("DID document id or verificationMethod is invalid");
  }
  const verificationMethod = document.verificationMethod.map((method) =>
    parseMethod(method, expectedDid),
  );
  const methods = new Map(verificationMethod.map((method) => [method.id, method]));
  return {
    id: expectedDid,
    verificationMethod,
    authentication: purposeEntries(document.authentication, methods),
    assertionMethod: purposeEntries(document.assertionMethod, methods),
  };
}

function relationshipContains(
  entries: (string | KyaVerificationMethod)[],
  methodId: string,
): boolean {
  return entries.some((entry) => (typeof entry === "string" ? entry : entry.id) === methodId);
}

export interface ProductionKyaDidResolverOptions {
  safeFetch?: SafeFetch;
  timeoutMs?: number;
  maxBytes?: number;
  maxRedirects?: number;
  cacheTtlMs?: number;
  now?: () => number;
}

export class ProductionKyaDidResolver implements KyaDidResolver {
  readonly #fetch: SafeFetch;
  readonly #cacheTtlMs: number;
  readonly #now: () => number;
  readonly #cache = new Map<string, { document: KyaDidDocument; expiresAt: number }>();

  constructor(options: ProductionKyaDidResolverOptions = {}) {
    this.#fetch =
      options.safeFetch ??
      createSafeFetch({
        timeoutMs: options.timeoutMs ?? 5_000,
        maxBytes: options.maxBytes ?? 1_048_576,
        maxRedirects: options.maxRedirects ?? 3,
      });
    // Trust-bearing DID material is not cached by default. A caller may choose
    // a bounded TTL only when it can prove that the TTL cannot outlive the
    // request proof or delegation validity window.
    this.#cacheTtlMs = options.cacheTtlMs ?? 0;
    this.#now = options.now ?? Date.now;
  }

  async resolveDidDocument(did: string): Promise<KyaDidDocument> {
    const cached = this.#cache.get(did);
    if (cached !== undefined && cached.expiresAt > this.#now()) return cached.document;

    let raw: unknown;
    if (did.startsWith("did:key:")) {
      raw = resolveDidKeySync(did);
      if (raw === null) throw new TypeError("Unsupported or malformed did:key");
    } else if (did.startsWith("did:web:")) {
      const url = didWebUrl(did);
      const response = await this.#fetch(url);
      if (!response.ok) throw new TypeError(`did:web resolution returned HTTP ${response.status}`);
      raw = await response.json();
    } else {
      throw new TypeError("Unsupported DID method");
    }

    const document = parseDidDocument(raw, did);
    if (this.#cacheTtlMs > 0) {
      this.#cache.set(did, { document, expiresAt: this.#now() + this.#cacheTtlMs });
    }
    return document;
  }

  async resolveVerificationMethod(kid: string): Promise<KyaVerificationMethod> {
    const separator = kid.indexOf("#");
    if (separator <= 0 || separator === kid.length - 1) {
      throw new TypeError("An exact DID key fragment is required");
    }
    const did = kid.slice(0, separator);
    const document = await this.resolveDidDocument(did);
    const method = document.verificationMethod.find((candidate) => candidate.id === kid);
    if (method === undefined)
      throw new TypeError("Verification method is not published by the DID");
    if (
      !relationshipContains(document.authentication, kid) &&
      !relationshipContains(document.assertionMethod, kid)
    ) {
      throw new TypeError("Verification method is not authorised for authentication or assertion");
    }
    return method;
  }

  async resolveDidKeys(did: string): Promise<ProofPublicJwk[]> {
    const document = await this.resolveDidDocument(did);
    return document.verificationMethod.flatMap((method) =>
      method.publicKeyJwk === undefined ? [] : [method.publicKeyJwk],
    );
  }
}

export function assertAssertionMethod(document: KyaDidDocument, kid: string): void {
  if (!relationshipContains(document.assertionMethod, kid)) {
    throw new KyaAuthorityError(
      "KYA_DELEGATION_SIGNATURE_INVALID",
      "delegation_signature",
      "Delegation verification method is not authorised for assertionMethod",
    );
  }
}

export function didWebUrl(did: string): string {
  if (!did.startsWith("did:web:")) throw new TypeError("Not a did:web DID");
  const segments = did.slice("did:web:".length).split(":").map(decodeURIComponent);
  const authority = segments.shift();
  if (authority === undefined || authority === "") throw new TypeError("Malformed did:web DID");
  const suffix =
    segments.length === 0 ? "/.well-known/did.json" : `/${segments.join("/")}/did.json`;
  return new URL(suffix, `https://${authority}`).toString();
}
