import { ProductionKyaDidResolver, didWebUrl } from "@inntris/kya-os-authority";
import { createSafeFetch, type SafeFetch } from "@kya-os/mcp/card";
import { describe, expect, it } from "vitest";

import { deterministicDidKey } from "../kya-helpers.js";

describe("production KYA DID resolver", () => {
  it("resolves a local Ed25519 did:key and exact fragment", async () => {
    const identity = deterministicDidKey(21);
    const resolver = new ProductionKyaDidResolver();
    const method = await resolver.resolveVerificationMethod(identity.kid);
    expect(method).toMatchObject({ id: identity.kid, controller: identity.did });
    await expect(resolver.resolveVerificationMethod(`${identity.did}#wrong`)).rejects.toThrow();
  });

  it("resolves did:web through the injected safe fetch and checks controller", async () => {
    const key = deterministicDidKey(22);
    const did = "did:web:agent.example";
    const kid = `${did}#key-1`;
    let requested = "";
    const safeFetch: SafeFetch = async (url) => {
      requested = url;
      return {
        ok: true,
        status: 200,
        json: async () => ({
          id: did,
          verificationMethod: [
            {
              id: kid,
              type: "JsonWebKey2020",
              controller: did,
              publicKeyJwk: {
                kty: "OKP",
                crv: "Ed25519",
                x: key.privateJwk.x,
              },
            },
          ],
          authentication: [kid],
          assertionMethod: [kid],
        }),
      };
    };
    const resolver = new ProductionKyaDidResolver({ safeFetch });
    expect(await resolver.resolveVerificationMethod(kid)).toMatchObject({
      id: kid,
      controller: did,
    });
    expect(requested).toBe("https://agent.example/.well-known/did.json");
  });

  it("fails closed on a DID document identity or controller mismatch", async () => {
    const safeFetch: SafeFetch = async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        id: "did:web:other.example",
        verificationMethod: [],
        authentication: [],
        assertionMethod: [],
      }),
    });
    await expect(
      new ProductionKyaDidResolver({ safeFetch }).resolveDidDocument("did:web:agent.example"),
    ).rejects.toThrow();
    expect(didWebUrl("did:web:example.com:agents:alice")).toBe(
      "https://example.com/agents/alice/did.json",
    );
  });

  it("rejects malformed keys, missing fragments and private did:web destinations", async () => {
    const resolver = new ProductionKyaDidResolver();
    await expect(resolver.resolveDidDocument("did:key:not-a-valid-key")).rejects.toThrow();
    await expect(resolver.resolveVerificationMethod("did:key:not-a-valid-key")).rejects.toThrow(
      "fragment",
    );

    const guarded = createSafeFetch({
      lookup: async () => [{ address: "127.0.0.1", family: 4 }],
      transport: async () => {
        throw new Error("Blocked destinations must not reach the transport");
      },
    });
    await expect(
      new ProductionKyaDidResolver({ safeFetch: guarded }).resolveDidDocument(
        "did:web:private.example",
      ),
    ).rejects.toThrow();
  });
});
