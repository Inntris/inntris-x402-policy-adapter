import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  InMemoryKyaNonceStore,
  KYA_REFERENCE_PACKAGE_VERSION,
  ProductionKyaDidResolver,
  UpstreamKyaRequestProofVerifier,
} from "@inntris/kya-os-authority";
import {
  CardProofMetaSchema,
  DelegationCredentialSchema,
  validateDelegationChain,
} from "@kya-os/mcp/card";
import { resolveDidKeySync } from "@kya-os/mcp/delegation";
import { describe, expect, it } from "vitest";

import { MutableClock } from "../helpers.js";
import { buildKyaFixture, KYA_AUDIENCE, KYA_NOW, KYA_TARGET } from "../kya-helpers.js";

describe("pinned KYA upstream compatibility", () => {
  it("exercises the exact 1.12.0 proof, DID and delegation public surfaces", async () => {
    const packageEntry = fileURLToPath(import.meta.resolve("@kya-os/mcp"));
    const packageJson = JSON.parse(
      await readFile(resolve(dirname(packageEntry), "../package.json"), "utf8"),
    ) as { version?: unknown };
    expect(packageJson.version).toBe(KYA_REFERENCE_PACKAGE_VERSION);
    expect(packageJson.version).toBe("1.12.0");

    const fixture = await buildKyaFixture({ nonce: "AQIDBAUGBwgJCgsMDQ4POw" });
    expect(CardProofMetaSchema.parse(fixture.presentation.request_proof)).toBeDefined();
    expect(DelegationCredentialSchema.parse(fixture.delegation)).toBeDefined();
    expect(resolveDidKeySync(fixture.agent.did)?.id).toBe(fixture.agent.did);
    expect(
      validateDelegationChain([DelegationCredentialSchema.parse(fixture.delegation)], {
        maxDepth: 10,
        now: () => KYA_NOW.getTime(),
        resource: KYA_TARGET,
      }),
    ).toMatchObject({
      ok: true,
      leafInvoker: fixture.agent.did,
      responsibleParty: fixture.root.did,
      invocationTarget: KYA_TARGET,
    });

    await expect(
      new UpstreamKyaRequestProofVerifier({
        resolver: new ProductionKyaDidResolver(),
        nonceStore: new InMemoryKyaNonceStore(),
        clock: new MutableClock(KYA_NOW),
      }).verify({
        proof: fixture.presentation.request_proof,
        request: fixture.presentation.request,
        expectedAudience: KYA_AUDIENCE,
      }),
    ).resolves.toMatchObject({ did: fixture.agent.did, assurance: "L3-minus" });
  });
});
