import { hashAction } from "@inntris/decision-core";
import { actionFromX402, X402BindingError, type X402SettlementInput } from "@inntris/x402-adapter";
import { afterAll, describe, expect, it } from "vitest";

import { honestInput, honestRequirements, paymentPayload, securityContext } from "./harness.js";
import { flushEvidence, recordEvidence } from "./evidence.js";
import { CORPUS_SEED } from "./global-setup.js";

afterAll(async () => {
  await flushEvidence("d4-mutation-corpus");
});

/** Deterministic generator so the corpus is identical between runs. */
function seededRandom(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state * 1_664_525 + 1_013_904_223) >>> 0;
    return state / 0x1_0000_0000;
  };
}

type MutationKind = "integrity" | "binding" | "type-encoding";

interface Mutation {
  id: string;
  kind: MutationKind;
  /** True when the mutated field changes what a payment actually does. */
  policyBearing: boolean;
  apply: (input: X402SettlementInput) => X402SettlementInput;
}

const REQUIREMENTS_FIELDS = [
  "amount",
  "asset",
  "network",
  "payTo",
  "scheme",
  "maxTimeoutSeconds",
] as const;
const PAYLOAD_FIELDS = ["to", "value", "from", "validBefore", "nonce", "signature"] as const;

const TYPE_VALUES: { label: string; value: unknown }[] = [
  { label: "number-for-string", value: 4500000 },
  { label: "leading-zeros", value: "0004500000" },
  { label: "scientific", value: "4.5e6" },
  { label: "oversized-integer", value: "9".repeat(40) },
  { label: "null", value: null },
  { label: "absent", value: undefined },
  { label: "empty-string", value: "" },
  { label: "negative", value: "-4500000" },
];

function buildCorpus(): Mutation[] {
  const random = seededRandom(CORPUS_SEED);
  const corpus: Mutation[] = [];

  // Integrity: mutate the requirements without touching the payload, so the
  // payload's `accepted` echo no longer agrees.
  for (const field of REQUIREMENTS_FIELDS) {
    corpus.push({
      id: `integrity:requirements.${field}`,
      kind: "integrity",
      policyBearing: field !== "maxTimeoutSeconds" && field !== "scheme",
      apply: (input) => ({
        ...input,
        paymentRequirements: {
          ...input.paymentRequirements,
          [field]:
            field === "maxTimeoutSeconds" ? 999 : `mutated-${field}-${Math.floor(random() * 1e6)}`,
        },
        paymentPayload: paymentPayload({ accepted: honestRequirements }),
      }),
    });
  }

  // Binding: mutate the requirements and re-issue a payload that agrees with
  // them, which is what a payer able to re-sign would produce.
  for (const field of REQUIREMENTS_FIELDS) {
    corpus.push({
      id: `binding:requirements.${field}`,
      kind: "binding",
      policyBearing: field !== "maxTimeoutSeconds" && field !== "scheme",
      apply: (input) => {
        const requirements = {
          ...input.paymentRequirements,
          ...(field === "maxTimeoutSeconds"
            ? { maxTimeoutSeconds: 999 }
            : field === "amount"
              ? { amount: "9000000" }
              : { [field]: `mutated-${field}` }),
        };
        return {
          ...input,
          paymentRequirements: requirements,
          paymentPayload: paymentPayload({ accepted: requirements }),
        };
      },
    });
  }

  // Binding: mutate the inner signed authorisation, leaving `accepted` intact.
  for (const field of PAYLOAD_FIELDS) {
    corpus.push({
      id: `binding:authorization.${field}`,
      kind: "binding",
      policyBearing: field === "to" || field === "value",
      apply: (input) => ({
        ...input,
        paymentPayload: paymentPayload({
          [field]: field === "validBefore" ? "1" : `0x${"ee".repeat(20)}`,
        }),
      }),
    });
  }

  // Type and encoding, across both requirements and the caller-declared
  // precision that F-1 identified.
  for (const field of ["amount", "payTo", "network"] as const) {
    for (const variant of TYPE_VALUES) {
      corpus.push({
        id: `type-encoding:requirements.${field}:${variant.label}`,
        kind: "type-encoding",
        policyBearing: true,
        apply: (input) => {
          const source = input.paymentRequirements as unknown as Record<string, unknown>;
          // An absent field is modelled by rebuilding without it, rather than
          // by deleting a computed key from a copy.
          const requirements = Object.fromEntries(
            Object.entries(source).filter(
              ([key]) => !(variant.value === undefined && key === field),
            ),
          );
          if (variant.value !== undefined) requirements[field] = variant.value;
          return {
            ...input,
            paymentRequirements: requirements as unknown as typeof honestRequirements,
          };
        },
      });
    }
  }
  for (const decimals of [0, 1, 9, 12, 18]) {
    corpus.push({
      id: `type-encoding:assetDecimals:${decimals}`,
      kind: "type-encoding",
      policyBearing: true,
      apply: (input) => ({ ...input, assetDecimals: decimals }),
    });
  }

  return corpus;
}

const CORPUS = buildCorpus();

describe("D4 systematic mutation corpus", () => {
  it(`generates a deterministic corpus from seed ${CORPUS_SEED}`, () => {
    expect(CORPUS.length).toBeGreaterThan(30);
    expect(CORPUS.length).toBeLessThan(400);
    expect(new Set(CORPUS.map((mutation) => mutation.id)).size).toBe(CORPUS.length);
  });

  it("asserts the property: a policy-bearing mutation changes the decision or is rejected", async () => {
    const context = await securityContext();
    const baseline = await context.guard.authorise(honestInput);
    const baselineActionHash = hashAction(actionFromX402(honestInput));

    const silent: string[] = [];
    const rejected: string[] = [];
    const changed: string[] = [];

    for (const mutation of CORPUS) {
      const mutatedInput = mutation.apply(honestInput);
      let decision;
      try {
        decision = await context.guard.authorise(mutatedInput);
      } catch (error) {
        rejected.push(
          `${mutation.id} -> ${error instanceof X402BindingError ? "X402BindingError" : (error as Error).name}`,
        );
        continue;
      }

      const decisionChanged =
        decision.verdict !== baseline.verdict ||
        decision.action_hash !== baselineActionHash ||
        decision.transaction.amount !== baseline.transaction.amount ||
        decision.transaction.payee !== baseline.transaction.payee ||
        decision.transaction.asset !== baseline.transaction.asset ||
        decision.transaction.network !== baseline.transaction.network;

      if (!decisionChanged && mutation.policyBearing) {
        // The F-1 signature generalised: a policy-bearing value differs while
        // the decision and every hash stay identical.
        silent.push(mutation.id);
      } else {
        changed.push(mutation.id);
      }
    }

    recordEvidence({
      id: "D4:property-policy-bearing-mutation",
      deliverable: "D4",
      attack:
        "Property: for any mutation of a policy-bearing field, the decision changes or the request is rejected",
      status: silent.length === 0 ? "PASS" : "KNOWN_GAP",
      expectation:
        "No mutation may alter a policy-bearing value while producing an identical decision and identical hashes.",
      observed: `corpus of ${CORPUS.length} mutations from seed ${CORPUS_SEED}: ${rejected.length} rejected before a decision, ${changed.length} changed the decision, ${silent.length} silent. ${silent.length === 0 ? "No silent policy-bearing mutation was found. See D4:property-limit — this does not mean policy-bearing values cannot be manipulated." : `Silent: ${silent.join("; ")}`}`,
      enforcement: silent.length === 0 ? "INNTRIS" : "NONE",
      reason_codes: [],
      settlement_invoked: false,
      resource_served: false,
      notes: `Rejected sample: ${rejected.slice(0, 6).join("; ")}`,
    });

    // Recorded as measured; a silent mutation is evidence, not a broken test.
    expect(CORPUS.length).toBe(rejected.length + changed.length + silent.length);
  });

  it("records the limit of the property: F-1 satisfies it and is still a bypass", async () => {
    const context = await securityContext();
    const baseline = await context.guard.authorise(honestInput);
    const rescaled = await context.guard.authorise({ ...honestInput, assetDecimals: 9 });

    // The decision does change — which is exactly why the property passes.
    expect(rescaled.transaction.amount).not.toBe(baseline.transaction.amount);
    expect(rescaled.transaction.amount).toBe("0.0045");
    expect(rescaled.verdict).toBe("ALLOW");

    recordEvidence({
      id: "D4:property-limit",
      deliverable: "D4",
      attack: "Limit of the mutation property as specified",
      status: "KNOWN_GAP",
      expectation:
        "A zero-silent-mutation result should not be read as evidence that policy-bearing values cannot be manipulated.",
      observed:
        "The property is `decision changes OR request rejected`. F-1 changes the decision — 4.50 becomes 0.0045 at assetDecimals=9 — so it satisfies the property while remaining a complete limit bypass. The property detects a value that moves without trace; it does not detect a value that moves to a false but internally consistent figure. The zero-silent result in D4:property-policy-bearing-mutation must be read with that limit attached.",
      enforcement: "NONE",
      reason_codes: rescaled.reason_codes,
      settlement_invoked: false,
      resource_served: false,
      notes:
        "A property that would catch F-1 needs an independent source of truth for the decimal amount, which is the asset registry F-1's remediation calls for. It cannot be expressed against the current inputs alone.",
    });
  });

  it("records how the corpus splits by mutation kind", async () => {
    const context = await securityContext();
    const byKind: Record<MutationKind, { rejected: number; accepted: number }> = {
      integrity: { rejected: 0, accepted: 0 },
      binding: { rejected: 0, accepted: 0 },
      "type-encoding": { rejected: 0, accepted: 0 },
    };

    for (const mutation of CORPUS) {
      try {
        await context.guard.authorise(mutation.apply(honestInput));
        byKind[mutation.kind].accepted += 1;
      } catch {
        byKind[mutation.kind].rejected += 1;
      }
    }

    recordEvidence({
      id: "D4:kind-breakdown",
      deliverable: "D4",
      attack: "Mutation corpus outcome by kind",
      status: "PASS",
      expectation: "Each mutation kind's disposition is recorded rather than assumed.",
      observed: (Object.entries(byKind) as [MutationKind, { rejected: number; accepted: number }][])
        .map(
          ([kind, counts]) => `${kind}: ${counts.rejected} rejected, ${counts.accepted} accepted`,
        )
        .join("; "),
      enforcement: "INNTRIS",
      reason_codes: [],
      settlement_invoked: false,
      resource_served: false,
      notes:
        "An accepted mutation is not a failure by itself — it is a failure only when the mutated value was policy-bearing and the decision did not change, which the property case measures.",
    });

    expect(byKind.integrity.rejected).toBeGreaterThan(0);
  });
});
