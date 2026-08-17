import { hashAction, type InntrisDecisionV1 } from "@inntris/decision-core";
import { verifySignedDecision } from "@inntris/decision-verifier";
import { actionFromX402, type X402SettlementInput } from "@inntris/x402-adapter";
import { afterAll, describe, expect, it } from "vitest";

import {
  honestInput,
  honestRequirements,
  paymentPayload,
  securityContext,
  type SecurityContext,
} from "./harness.js";
import { flushEvidence, recordEvidence } from "./evidence.js";

afterAll(async () => {
  await flushEvidence("d2-provenance");
});

/**
 * Where a value comes from at the moment Inntris consumes it. Only
 * `signature-derived`, `chain-read` and `registry-resolved` are outside the
 * caller's control; the rest are assertions the caller makes.
 */
type Source =
  | "client-asserted"
  | "server-config"
  | "signature-derived"
  | "chain-read"
  | "registry-resolved"
  | "facilitator-asserted"
  | "derived-from-client-asserted";

interface FieldProbe {
  path: string;
  /** Applies a different, well-formed value. */
  mutate: (input: X402SettlementInput) => X402SettlementInput;
  /**
   * Applies a value organisational policy should refuse, where a rule for this
   * field exists. Omitted when no rule references the field at all.
   */
  hostile?: (input: X402SettlementInput) => X402SettlementInput;
  source: Source;
  attackerControllable: "yes" | "no" | "partially";
  /** What, if anything, checks the value. Written from the traced code path. */
  validatedAgainst: string;
  notes?: string;
}

/**
 * Attaches a payload whose `accepted` block mirrors the (possibly mutated)
 * requirements, so a requirements probe measures that field alone rather than
 * tripping the payload/requirements equality check on its way through.
 * A probe that supplies its own payload keeps it.
 */
const normaliseForProbe = (input: X402SettlementInput): X402SettlementInput =>
  input.paymentPayload === undefined
    ? { ...input, paymentPayload: paymentPayload({ accepted: input.paymentRequirements }) }
    : input;

const requirementsField = (
  overrides: Partial<typeof honestRequirements>,
): ((input: X402SettlementInput) => X402SettlementInput) => {
  return (input) => ({
    ...input,
    paymentRequirements: { ...input.paymentRequirements, ...overrides },
  });
};

/**
 * Every field that reaches a policy decision, an action or requirements hash,
 * or the signed receipt. Sources and controllability are traced from the code
 * path, and the reach columns are measured rather than asserted.
 */
const PROBES: FieldProbe[] = [
  {
    path: "paymentRequirements.amount",
    mutate: requirementsField({ amount: "4600000" }),
    hostile: requirementsField({ amount: "150000000" }),
    source: "client-asserted",
    attackerControllable: "yes",
    validatedAgainst:
      "policy per-transaction and daily limits, after conversion by the caller-declared assetDecimals",
  },
  {
    path: "paymentRequirements.asset",
    mutate: requirementsField({ asset: "USDC.e" }),
    hostile: requirementsField({ asset: "DAI" }),
    source: "client-asserted",
    attackerControllable: "yes",
    validatedAgainst: "policy rails.x402.allowed_assets, an exact string match",
    notes:
      "The demo policy allowlists the symbol `USDC`, not a chain-scoped contract address. Matching a symbol means the allowlist is applied to an unauthenticated label.",
  },
  {
    path: "paymentRequirements.network",
    mutate: requirementsField({ network: "eip155:1" }),
    hostile: requirementsField({ network: "eip155:84532" }),
    source: "client-asserted",
    attackerControllable: "yes",
    validatedAgainst: "policy rails.x402.allowed_networks, plus CAIP-2 shape at schema parse",
  },
  {
    path: "paymentRequirements.payTo",
    mutate: requirementsField({ payTo: "0x0000000000000000000000000000000000000009" }),
    hostile: requirementsField({ payTo: "0x00000000000000000000000000000000000000ff" }),
    source: "client-asserted",
    attackerControllable: "yes",
    validatedAgainst: "policy merchant payee allowlist",
  },
  {
    path: "paymentRequirements.scheme",
    mutate: requirementsField({ scheme: "deferred" }),
    source: "client-asserted",
    attackerControllable: "yes",
    validatedAgainst:
      "NOTHING. Carried into the receipt and the requirements hash; no policy rule and no allowlist references it.",
  },
  {
    path: "paymentRequirements.maxTimeoutSeconds",
    mutate: requirementsField({ maxTimeoutSeconds: 3600 }),
    source: "client-asserted",
    attackerControllable: "yes",
    validatedAgainst:
      "NOTHING beyond schema shape. Bound into the requirements hash but never compared to the decision TTL.",
  },
  {
    path: "paymentRequirements.extra",
    mutate: requirementsField({ extra: { name: "USDC", version: "2" } }),
    source: "client-asserted",
    attackerControllable: "yes",
    validatedAgainst:
      "NOTHING beyond schema shape. Free-form record bound into the requirements hash.",
  },
  {
    path: "resource",
    mutate: (input) => ({ ...input, resource: "https://example.test/other" }),
    hostile: (input) => ({ ...input, resource: "https://attacker.test/research" }),
    source: "client-asserted",
    attackerControllable: "yes",
    validatedAgainst: "policy merchant resource allowlist, an exact URL match",
  },
  {
    path: "purpose",
    mutate: (input) => ({ ...input, purpose: "research_api_v2" }),
    hostile: (input) => ({ ...input, purpose: "exfiltration" }),
    source: "client-asserted",
    attackerControllable: "yes",
    validatedAgainst: "policy merchant purpose allowlist",
  },
  {
    path: "principalId",
    mutate: (input) => ({ ...input, principalId: "org_other" }),
    source: "client-asserted",
    attackerControllable: "yes",
    validatedAgainst:
      "NOTHING. Used as the cumulative daily-spend key, so a new value starts a fresh daily budget.",
  },
  {
    path: "agentId",
    mutate: (input) => ({ ...input, agentId: "agent_impostor" }),
    source: "client-asserted",
    attackerControllable: "yes",
    validatedAgainst:
      "NOTHING on the local policy path. Carried into the receipt; evaluatePolicy never reads it. The KYA gate binds it separately on the KYA path only.",
  },
  {
    path: "assetDecimals",
    mutate: (input) => ({ ...input, assetDecimals: 9 }),
    source: "client-asserted",
    attackerControllable: "yes",
    validatedAgainst:
      "NOTHING beyond an integer range of 0 to 18. Not derived from the asset and not recorded in the receipt.",
    notes: "Finding F-1.",
  },
  {
    path: "extensions",
    mutate: (input) => ({ ...input, extensions: { "com.example/tag": "x" } }),
    source: "client-asserted",
    attackerControllable: "yes",
    validatedAgainst:
      "Reserved KYA key is rejected on the KYA path; otherwise a free-form record carried into the action hash and receipt.",
  },
  {
    path: "paymentPayload.payload.authorization.to",
    mutate: (input) => ({
      ...input,
      paymentPayload: paymentPayload({ to: "0x00000000000000000000000000000000000000ff" }),
    }),
    source: "signature-derived",
    attackerControllable: "partially",
    validatedAgainst:
      "NOTHING inside Inntris. Bound only as part of the opaque payload hash; the facilitator is the sole checker.",
    notes: "Finding F-4.",
  },
  {
    path: "paymentPayload.payload.authorization.value",
    mutate: (input) => ({ ...input, paymentPayload: paymentPayload({ value: "1" }) }),
    source: "signature-derived",
    attackerControllable: "partially",
    validatedAgainst: "NOTHING inside Inntris. See F-4.",
  },
  {
    path: "paymentPayload.payload.authorization.validBefore",
    mutate: (input) => ({ ...input, paymentPayload: paymentPayload({ validBefore: "1" }) }),
    source: "signature-derived",
    attackerControllable: "partially",
    validatedAgainst:
      "NOTHING inside Inntris. Never compared with the decision expiry, so an authorisation may outlive or predecease the decision that approved it.",
  },
  {
    path: "paymentPayload.payload.signature",
    mutate: (input) => ({
      ...input,
      paymentPayload: paymentPayload({ signature: `0x${"22".repeat(65)}` }),
    }),
    source: "signature-derived",
    attackerControllable: "partially",
    validatedAgainst: "NOTHING inside Inntris. Signature validity is entirely the facilitator's.",
  },
  {
    path: "paymentPayload.resource.url",
    mutate: (input) => ({
      ...input,
      paymentPayload: paymentPayload({ resourceUrl: "https://attacker.test/elsewhere" }),
    }),
    source: "client-asserted",
    attackerControllable: "yes",
    validatedAgainst:
      "NOTHING. Never compared with the `resource` field that policy actually evaluates.",
  },
  {
    path: "paymentPayload.accepted",
    mutate: (input) => ({
      ...input,
      paymentPayload: paymentPayload({
        accepted: { ...honestRequirements, payTo: "0x00000000000000000000000000000000000000ff" },
      }),
    }),
    source: "client-asserted",
    attackerControllable: "yes",
    validatedAgainst:
      "Equality with the quoted paymentRequirements hash, enforced in actionFromX402 before the action is built.",
  },
];

interface Reach {
  action_hash: boolean;
  requirements_hash: boolean;
  payload_hash: boolean;
  receipt: boolean;
  verdict: boolean;
}

function reachOf(
  baseline: X402SettlementInput,
  probe: FieldProbe,
): Reach | { binding_rejected: string } {
  const base = actionFromX402(normaliseForProbe(baseline));
  let mutated;
  try {
    mutated = actionFromX402(normaliseForProbe(probe.mutate(baseline)));
  } catch (error) {
    return { binding_rejected: (error as Error).message };
  }
  return {
    action_hash: hashAction(base) !== hashAction(mutated),
    requirements_hash:
      base.protocol_reference.payment_requirements_hash !==
      mutated.protocol_reference.payment_requirements_hash,
    payload_hash:
      base.protocol_reference.payment_payload_hash !==
      mutated.protocol_reference.payment_payload_hash,
    receipt: JSON.stringify(base) !== JSON.stringify(mutated),
    verdict: false,
  };
}

async function verdictOf(
  context: SecurityContext,
  input: X402SettlementInput,
): Promise<InntrisDecisionV1> {
  return context.guard.authorise(input);
}

describe("D2 input provenance", () => {
  it("classifies every field that reaches a decision, a hash or the receipt", async () => {
    // Probes are applied to the payload-free input; a matching payload is
    // attached afterwards so payload-bearing fields stay reachable.
    const baseline = honestInput;
    const rows: Record<string, unknown>[] = [];

    for (const probe of PROBES) {
      const measured = reachOf(baseline, probe);
      if ("binding_rejected" in measured) {
        rows.push({
          field_path: probe.path,
          reaches: "rejected before the action is built",
          source: probe.source,
          attacker_controllable: probe.attackerControllable,
          validated_against: probe.validatedAgainst,
          verdict_sensitivity: `X402BindingError: ${measured.binding_rejected}`,
        });
        recordEvidence({
          id: `D2:${probe.path}`,
          deliverable: "D2",
          attack: `Provenance of ${probe.path}`,
          status: "PASS",
          expectation:
            "Every field reaching a decision, hash or receipt is classified by source, controllability and validation.",
          observed: `mutation rejected before the action is built: ${measured.binding_rejected}`,
          enforcement: "INNTRIS",
          reason_codes: [],
          settlement_invoked: false,
          resource_served: false,
          ...(probe.notes === undefined ? {} : { notes: probe.notes }),
        });
        continue;
      }
      const reach = measured;

      // Verdict sensitivity is measured with a value policy should refuse,
      // where a rule for the field exists at all.
      let verdictSensitive = false;
      let verdictDetail = "no policy rule references this field";
      if (probe.hostile !== undefined) {
        const context = await securityContext();
        const clean = await verdictOf(context, normaliseForProbe(baseline));
        const hostile = await verdictOf(context, normaliseForProbe(probe.hostile(baseline)));
        verdictSensitive = clean.verdict !== hostile.verdict;
        verdictDetail = `${clean.verdict} -> ${hostile.verdict} (${hostile.reason_codes.join(", ")})`;
      }
      reach.verdict = verdictSensitive;

      rows.push({
        field_path: probe.path,
        reaches: [
          reach.action_hash ? "action-hash" : undefined,
          reach.requirements_hash ? "requirements-hash" : undefined,
          reach.payload_hash ? "payload-hash" : undefined,
          reach.receipt ? "receipt" : undefined,
          reach.verdict ? "decision" : undefined,
        ]
          .filter(Boolean)
          .join(", "),
        source: probe.source,
        attacker_controllable: probe.attackerControllable,
        validated_against: probe.validatedAgainst,
        verdict_sensitivity: verdictDetail,
        ...(probe.notes === undefined ? {} : { notes: probe.notes }),
      });

      recordEvidence({
        id: `D2:${probe.path}`,
        deliverable: "D2",
        attack: `Provenance of ${probe.path}`,
        status: "PASS",
        expectation:
          "Every field reaching a decision, hash or receipt is classified by source, controllability and validation.",
        observed: `reaches [${rows[rows.length - 1]?.reaches as string}]; source ${probe.source}; attacker-controllable ${probe.attackerControllable}; validated against ${probe.validatedAgainst}`,
        enforcement: probe.validatedAgainst.startsWith("NOTHING") ? "NONE" : "INNTRIS",
        reason_codes: [],
        settlement_invoked: false,
        resource_served: false,
        ...(probe.notes === undefined ? {} : { notes: probe.notes }),
      });
    }

    // No field may be left unclassified.
    expect(rows).toHaveLength(PROBES.length);
    for (const row of rows) {
      expect(row.source).not.toBe("unknown");
      expect(row.reaches).not.toBe("");
    }
  });

  it("confirms unvalidated fields still reach the signed receipt", async () => {
    const context = await securityContext();

    // `scheme` and `maxTimeoutSeconds` are bound but never evaluated.
    const decision = await context.guard.authorise(
      normaliseForProbe({
        ...honestInput,
        paymentRequirements: {
          ...honestInput.paymentRequirements,
          scheme: "deferred",
          maxTimeoutSeconds: 86_400,
        },
      }),
    );

    expect(decision.verdict).toBe("ALLOW");
    expect(decision.protocol_reference).toMatchObject({ scheme: "deferred" });
    expect(verifySignedDecision(decision, context.keyRegistry).valid).toBe(true);

    recordEvidence({
      id: "D2:unevaluated-fields-in-receipt",
      deliverable: "D2",
      attack: "Fields bound into the receipt that no policy rule evaluates",
      status: "KNOWN_GAP",
      expectation:
        "A field carried into a signed receipt should either be evaluated by policy or be documented as decorative.",
      observed:
        "scheme=deferred and maxTimeoutSeconds=86400 produced a valid, signed ALLOW. The scheme reaches protocol_reference and the requirements hash; no policy rule references either field.",
      enforcement: "NONE",
      reason_codes: decision.reason_codes,
      settlement_invoked: false,
      resource_served: false,
      notes:
        "A reader of the receipt may reasonably infer that a named scheme was approved as such. It was not evaluated.",
    });
  });

  it("shows the cumulative daily budget is keyed on a client-asserted principal", async () => {
    const context = await securityContext();
    const first = await context.guard.authorise(honestInput);
    const other = await context.guard.authorise({ ...honestInput, principalId: "org_other" });

    expect(first.verdict).toBe("ALLOW");
    expect(other.verdict).toBe("ALLOW");
    expect(other.principal_id).toBe("org_other");

    recordEvidence({
      id: "D2:principal-keyed-budget",
      deliverable: "D2",
      attack: "Daily cumulative limit keyed on a caller-supplied principal identifier",
      status: "KNOWN_GAP",
      expectation:
        "A cumulative spending limit should be keyed on an identity the caller cannot choose.",
      observed:
        "principal_id is taken from the caller on the library path and from the request body on POST /v1/decisions/evaluate. spendDayKey uses it directly, so each distinct value carries its own independent daily total.",
      enforcement: "NONE",
      reason_codes: [],
      settlement_invoked: false,
      resource_served: false,
      notes:
        "Severity depends on who may call the endpoint; see D8. On the KYA path the principal is derived from the presentation instead.",
    });
  });

  it("shows agent identity reaches the receipt without reaching policy", async () => {
    const context = await securityContext();
    const honest = await context.guard.authorise(honestInput);
    const impostor = await context.guard.authorise({ ...honestInput, agentId: "agent_impostor" });

    expect(honest.verdict).toBe(impostor.verdict);
    expect(impostor.agent_id).toBe("agent_impostor");

    recordEvidence({
      id: "D2:agent-id-unevaluated",
      deliverable: "D2",
      attack: "Agent identifier carried into the receipt but not evaluated by policy",
      status: "KNOWN_GAP",
      expectation:
        "An agent identifier named in a signed decision should either constrain the decision or be documented as informational.",
      observed:
        "Changing agent_id changes the action hash and the receipt but not the verdict. evaluatePolicy never reads agent_id; the local policy schema has no per-agent rule.",
      enforcement: "NONE",
      reason_codes: [],
      settlement_invoked: false,
      resource_served: false,
      notes:
        "The KYA OS gate binds agent identity on its own path. This concerns the plain x402 path only.",
    });
  });
});
