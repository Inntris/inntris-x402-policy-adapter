import { describe, expect, it } from "vitest";
import {
  PULSE_BUNDLE_VERSION,
  calculateInputHash,
  evaluateCase,
  parseBlindedBundleBytes,
  type ConformanceCase,
  type StructuredAp2Verification,
} from "../../packages/pulse-conformance-evaluator/src/index.js";
import { makeConformanceCase, makeMockVerifier } from "./helpers.js";
import { realVerifier, signCase } from "./signed-helpers.js";

const now = 2_000_000_000;
function requestFor(input: ConformanceCase, clockSkewSeconds = 0) {
  return {
    ...input.ap2.verification.cryptographicEvidence,
    currentTimeEpoch: now,
    clockSkewSeconds,
  };
}
// Each group specifies its invariant, reason, expected outcome and exercised boundary.
describe("P0 JWT time: signed authority must be active [default Python bridge, reject AP2_MANDATE_TIME_INVALID]", () => {
  for (const stage of ["root", "leaf"] as const) {
    for (const [claim, value] of [
      ["nbf", now + 1],
      ["exp", now],
      ["iat", null],
      ["iat", "invalid"],
      ["exp", null],
      ["nbf", false],
      ["exp", "later"],
    ] as const) {
      it(`${stage} ${claim}=${String(value)} cannot grant active authority`, async () => {
        const input = await signCase({ [stage]: { [claim]: value } });
        const result = await evaluateCase(input, realVerifier);
        expect(result.decision).toBe("reject");
        expect(result.failureCodes).toContain("AP2_MANDATE_TIME_INVALID");
      });
    }
    it(`${stage} now equals nbf is valid [accept]`, async () => {
      expect(
        (await evaluateCase(await signCase({ [stage]: { nbf: now } }), realVerifier)).decision,
      ).toBe("accept");
    });
  }
  it("missing required terminal iat rejects [key binding category]", async () => {
    expect(
      (await evaluateCase(await signCase({ omitLeaf: ["iat"] }), realVerifier)).failureCodes,
    ).toContain("AP2_KEY_BINDING_UNVERIFIED");
  });
  it("receipt signed nbf cannot be ignored [receipt category]", async () => {
    expect(
      (await evaluateCase(await signCase({ receipt: { nbf: now + 1 } }), realVerifier))
        .failureCodes,
    ).toContain("AP2_RECEIPT_UNVERIFIED");
  });
});

describe("P0 skew boundaries [real Python bridge interface, evaluator profile still requires zero skew]", () => {
  for (const [claim, value, expectedStatus] of [
    ["nbf", now + 5, "verified"],
    ["nbf", now + 6, "invalid"],
    ["iat", now + 5, "verified"],
    ["iat", now + 6, "invalid"],
    ["exp", now - 4, "verified"],
    ["exp", now - 5, "invalid"],
  ] as const) {
    it(`${claim}=${value}, skew 5 => ${expectedStatus}`, async () => {
      const input = await signCase({ leaf: { [claim]: value } });
      expect((await realVerifier.verify(requestFor(input, 5))).mandateTime.status).toBe(
        expectedStatus,
      );
    });
  }
});

describe("P0 expiry composition: payment cannot outlive any signed authority [default bridge]", () => {
  for (const stage of ["root", "leaf"] as const) {
    it(`rejects validBefore beyond ${stage} wrapper [EIP3009_VALIDITY_EXCEEDS_AP2_EXPIRY]`, async () => {
      const result = await evaluateCase(
        await signCase({ [stage]: { exp: now + 299 } }),
        realVerifier,
      );
      expect(result.failureCodes).toEqual(["EIP3009_VALIDITY_EXCEEDS_AP2_EXPIRY"]);
    });
  }
  it("accepts equality with the earliest of all bounds", async () => {
    const input = await signCase({ root: { exp: now + 200 }, leaf: { exp: now + 250 } }, (c) => {
      c.x402.payload.payload.authorization.validBefore = String(now + 200);
    });
    expect((await evaluateCase(input, realVerifier)).decision).toBe("accept");
  });
  it("rejects one second beyond the earliest of differing bounds", async () => {
    const input = await signCase({ root: { exp: now + 200 }, leaf: { exp: now + 250 } }, (c) => {
      c.x402.payload.payload.authorization.validBefore = String(now + 201);
    });
    expect((await evaluateCase(input, realVerifier)).failureCodes).toEqual([
      "EIP3009_VALIDITY_EXCEEDS_AP2_EXPIRY",
    ]);
  });
  it("absent optional wrapper expiry keeps mandatory inner bounds [accept]", async () => {
    expect((await evaluateCase(await signCase(), realVerifier)).decision).toBe("accept");
  });
});

describe("P0 disclosures: tampered presentation must not be accepted [default bridge]", () => {
  for (const stage of ["root", "leaf"] as const) {
    for (const mode of ["orphan", "malformed", "duplicate", "tampered"]) {
      it(`${stage} ${mode} rejects [corresponding mandate unverified]`, async () => {
        const input = await signCase({ [`${stage}Disclosure`]: mode });
        const result = await evaluateCase(input, realVerifier);
        expect(result.decision).toBe("reject");
        expect(result.failureCodes).toContain(
          stage === "root" ? "AP2_OPEN_MANDATE_UNVERIFIED" : "AP2_CLOSED_MANDATE_UNVERIFIED",
        );
      });
    }
  }
  it("authenticated root and terminal disclosures remain valid [accept]", async () => {
    expect(
      (
        await evaluateCase(
          await signCase({ rootDisclosure: "valid", leafDisclosure: "valid" }),
          realVerifier,
        )
      ).decision,
    ).toBe("accept");
  });
  it("appending orphan bytes without resigning anything rejects", async () => {
    const input = await signCase();
    input.ap2.verification.cryptographicEvidence.mandateChain +=
      Buffer.from(JSON.stringify(["salt", "unsigned", "value"])).toString("base64url") + "~";
    input.inputHash = calculateInputHash(input);
    expect((await evaluateCase(input, realVerifier)).failureCodes).toContain(
      "AP2_CLOSED_MANDATE_UNVERIFIED",
    );
  });
});

function bundle(input: ConformanceCase): string {
  return JSON.stringify({
    bundleVersion: PULSE_BUNDLE_VERSION,
    sourcePins: input.sourcePins,
    generatedAt: "2033-05-18T03:33:20Z",
    cases: Array.from({ length: 80 }, (_, i) => ({ ...input, id: `raw-regression-${i}` })),
  });
}

describe("P0 raw JSON/JCS: ambiguity must reject before information loss [parser boundary]", () => {
  const mutations: [string, (s: string) => string][] = [
    [
      "duplicate ap2 concealing expected",
      (s) => s.replace('"ap2":{', '"ap2":{"expected":true},"ap2":{'),
    ],
    ["conflicting success", (s) => s.replace('"success":true', '"success":false,"success":true')],
    ["nested duplicate", (s) => s.replace('"scheme":"exact"', '"scheme":"wrong","scheme":"exact"')],
    [
      "escaped equivalent member",
      (s) => s.replace('"success":true', '"succ\\u0065ss":false,"success":true'),
    ],
    ["lone high surrogate", (s) => s.replace("Independent resource", "\\ud800")],
    ["lone low surrogate", (s) => s.replace("Independent resource", "\\udfff")],
  ];
  for (const [name, mutate] of mutations) {
    it(`${name} [reject parsing]`, async () => {
      const raw = mutate(bundle(await makeConformanceCase()));
      expect(() => parseBlindedBundleBytes(Buffer.from(raw))).toThrow();
    });
  }
  it("lone surrogate cannot be hashed through the object API", async () => {
    const input = await makeConformanceCase();
    input.x402.payload.resource.description = "\ud800";
    expect(() => calculateInputHash(input)).toThrow();
    expect((await evaluateCase(input, realVerifier)).failureCodes).toEqual([
      "INPUT_SCHEMA_INVALID",
    ]);
  });
  it("ordinary Unicode and canonical inputs remain valid [accept]", async () => {
    const input = await signCase();
    input.x402.payload.resource.description = "café 水 😀";
    input.inputHash = calculateInputHash(input);
    expect(parseBlindedBundleBytes(Buffer.from(bundle(input))).cases).toHaveLength(80);
    expect((await evaluateCase(input, realVerifier)).decision).toBe("accept");
  });
});

describe("P1 mandatory stages: an empty failure list is not verification [interface only]", () => {
  for (const stage of [
    "all",
    "openMandate",
    "closedMandate",
    "keyBinding",
    "mandateTime",
    "receipt",
    "missing",
  ]) {
    it(`${stage} unavailable must reject [cryptographic verification category]`, async () => {
      const input = await makeConformanceCase();
      const mock = makeMockVerifier(input);
      const result = await mock.verify({
        ...input.ap2.verification.cryptographicEvidence,
        currentTimeEpoch: now,
        clockSkewSeconds: 0,
      });
      const altered = result as unknown as Record<string, unknown>;
      if (stage === "missing") delete altered.keyBinding;
      else
        for (const name of stage === "all"
          ? ["openMandate", "closedMandate", "keyBinding", "mandateTime", "receipt"]
          : [stage])
          altered[name] = { status: "notEvaluated" };
      const evaluated = await evaluateCase(input, {
        verify: async () => altered as unknown as StructuredAp2Verification,
      });
      expect(evaluated.decision).toBe("reject");
      expect(evaluated.failureCodes.some((code) => code.startsWith("AP2_"))).toBe(true);
    });
  }
  it("all mandatory stages explicitly verified remains valid [accept]", async () => {
    const input = await makeConformanceCase();
    expect((await evaluateCase(input, makeMockVerifier(input))).decision).toBe("accept");
  });
});

describe("P1 independent failures: bad leaf cannot suppress authenticated root time [default bridge]", () => {
  it("expired root plus corrupt leaf preserves both categories in controlled order", async () => {
    const result = await evaluateCase(
      await signCase({ root: { exp: now - 1 }, corruptLeaf: true }),
      realVerifier,
    );
    expect(result.failureCodes).toContain("AP2_CLOSED_MANDATE_UNVERIFIED");
    expect(result.failureCodes).toContain("AP2_MANDATE_TIME_INVALID");
    expect(result.failureCodes.indexOf("AP2_CLOSED_MANDATE_UNVERIFIED")).toBeLessThan(
      result.failureCodes.indexOf("AP2_MANDATE_TIME_INVALID"),
    );
  });
  it("nonce, EIP signature and settlement failures remain independently applicable", async () => {
    const input = await signCase();
    input.ap2.verification.cryptographicEvidence.expectedNonce = "different";
    input.x402.payload.payload.signature = input.x402.payload.payload.signature.slice(0, -2) + "00";
    input.x402.settlement.success = false;
    input.x402.settlement.amount = "1";
    input.inputHash = calculateInputHash(input);
    expect((await evaluateCase(input, realVerifier)).failureCodes).toEqual([
      "AP2_KEY_BINDING_UNVERIFIED",
      "EIP3009_SIGNATURE_INVALID",
      "SETTLEMENT_FAILED",
      "SETTLEMENT_AMOUNT_MISMATCH",
    ]);
  });
});

describe("P2 optional merchant and producer independence [default bridge]", () => {
  const omitWebsites = (c: ConformanceCase): void => {
    Reflect.deleteProperty(c.ap2.closedMandate.payee, "website");
    for (const constraint of c.ap2.openMandate.constraints) {
      if (constraint.type === "payment.allowed_payees" && Array.isArray(constraint.allowed)) {
        for (const merchant of constraint.allowed as Record<string, unknown>[])
          Reflect.deleteProperty(merchant, "website");
      }
    }
  };
  it("matching merchant IDs without websites accept", async () => {
    expect((await evaluateCase(await signCase({}, omitWebsites), realVerifier)).decision).toBe(
      "accept",
    );
  });
  it("supplied invalid website rejects [schema category]", async () => {
    const input = await signCase({}, (c) => {
      c.ap2.closedMandate.payee.website = "not a URL";
    });
    expect((await evaluateCase(input, realVerifier)).failureCodes).toEqual([
      "INPUT_SCHEMA_INVALID",
    ]);
  });
  it("missing mandatory merchant identity rejects even without website", async () => {
    const input = await signCase({}, (c) => {
      omitWebsites(c);
      Reflect.deleteProperty(c.ap2.closedMandate.payee, "id");
    });
    expect((await evaluateCase(input, realVerifier)).failureCodes).toEqual([
      "INPUT_SCHEMA_INVALID",
    ]);
  });
  it("unsigned producer label cannot determine authority [accept]", async () => {
    const input = await signCase();
    input.ap2.verification.verifier = "independent-producer-label";
    input.inputHash = calculateInputHash(input);
    expect((await evaluateCase(input, realVerifier)).decision).toBe("accept");
  });
});

describe("Specification boundary observations, not authorisation guarantees [default bridge]", () => {
  it("records the concealed restriction ambiguity without defining an all-disclosure policy", async () => {
    const concealed = await evaluateCase(
      await signCase({ rootDisclosure: "concealed" }),
      realVerifier,
    );
    const revealed = await evaluateCase(
      await signCase({ rootDisclosure: "revealed" }),
      realVerifier,
    );
    expect(concealed.decision).toBe("accept");
    expect(revealed.failureCodes).toContain("AP2_CONSTRAINT_VIOLATION");
  });
  it("resource URL has shape validation but no separate authenticated expectation", async () => {
    const input = await signCase();
    input.x402.payload.resource.url = "https://different.example/resource";
    input.inputHash = calculateInputHash(input);
    expect((await evaluateCase(input, realVerifier)).decision).toBe("accept");
  });
  it("schema failure ends semantic applicability rather than speculatively inflating codes", async () => {
    const input = await signCase();
    Object.assign(input.x402.payload.resource, { unsupported: true });
    input.x402.settlement.success = false;
    input.inputHash = calculateInputHash(input);
    expect((await evaluateCase(input, realVerifier)).failureCodes).toEqual([
      "INPUT_SCHEMA_INVALID",
    ]);
  });
  it("independent signing is byte-for-byte deterministic", async () => {
    expect(await signCase({ rootDisclosure: "valid", leafDisclosure: "valid" })).toEqual(
      await signCase({ rootDisclosure: "valid", leafDisclosure: "valid" }),
    );
  });
});
