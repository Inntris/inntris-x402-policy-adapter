import { afterAll, describe, expect, it } from "vitest";

import {
  FakeFacilitator,
  GuardedResourceServer,
  honestInput,
  InMemorySpendState,
  paymentPayload,
  permissiveFacilitator,
  securityContext,
  withRequirements,
  type SecurityContextOptions,
} from "./harness.js";
import { flushEvidence, recordEvidence, type RunOutcome } from "./evidence.js";

afterAll(async () => {
  await flushEvidence("d6-configuration");
});

/**
 * Configurations reachable in practice. `reconciliationStore` absent is the
 * guard's own default and the one the documentation leaves optional.
 */
const CONFIGURATIONS: { label: string; options: SecurityContextOptions; unsafe: boolean }[] = [
  { label: "default (no reconciliation store)", options: {}, unsafe: true },
  { label: "reconciliation store configured", options: { reconciliation: true }, unsafe: false },
  {
    label: "no policy-version pin",
    options: { reconciliation: true, expectedPolicyVersion: undefined },
    unsafe: true,
  },
  {
    label: "accumulating spend state",
    options: { reconciliation: true, spendState: new InMemorySpendState() },
    unsafe: false,
  },
];

/** The core matrix, run under every configuration. */
const CORE = [
  {
    id: "replay-same-ref",
    name: "Settlement replay with the same execution reference",
    run: async (
      server: GuardedResourceServer,
      context: Awaited<ReturnType<typeof securityContext>>,
    ) => {
      const decision = await context.guard.authorise(honestInput);
      await server.access({
        authorisationInput: honestInput,
        payload: paymentPayload({}),
        executionRef: "d6-replay",
        decision,
      });
      return server.access({
        authorisationInput: honestInput,
        payload: paymentPayload({}),
        executionRef: "d6-replay",
        decision,
      });
    },
    mustReject: true,
  },
  {
    id: "settlement-failure",
    name: "Settlement failure bookkeeping",
    facilitator: () =>
      new FakeFacilitator("custom", {
        settle: () => ({ success: false, errorReason: "settlement_timeout" }),
      }),
    run: async (server: GuardedResourceServer) =>
      server.access({
        authorisationInput: honestInput,
        payload: paymentPayload({}),
        executionRef: "d6-settle-fail",
      }),
    mustReject: true,
  },
  {
    id: "post-authorisation-swap",
    name: "Payee swapped after authorisation",
    run: async (server: GuardedResourceServer) =>
      server.access({
        authorisationInput: honestInput,
        settlementInput: withRequirements({ payTo: "0x00000000000000000000000000000000000000ff" }),
        payload: paymentPayload({}),
        executionRef: "d6-swap",
      }),
    mustReject: true,
  },
];

describe("D6 configuration matrix", () => {
  for (const configuration of CONFIGURATIONS) {
    for (const testCase of CORE) {
      it(`${testCase.name} under ${configuration.label}`, async () => {
        const context = await securityContext(configuration.options);
        const facilitator = testCase.facilitator?.() ?? permissiveFacilitator();
        const server = new GuardedResourceServer(context, facilitator);
        const outcome: RunOutcome = await testCase.run(server, context);

        const rejected = outcome.rejected;
        recordEvidence({
          id: `D6:${testCase.id}:${configuration.label.replace(/[^a-z]+/gi, "-")}`,
          deliverable: "D6",
          attack: `${testCase.name} — configuration: ${configuration.label}`,
          status: rejected === testCase.mustReject ? "PASS" : "KNOWN_GAP",
          expectation: `Under every reachable configuration, this case must be ${testCase.mustReject ? "rejected" : "permitted"}.`,
          observed: rejected
            ? `rejected at ${outcome.layer} (${outcome.reason_codes.join(", ") || outcome.detail})`
            : `NOT REJECTED — ${outcome.detail}`,
          compliant: outcome,
          enforcement: rejected && outcome.layer.startsWith("INNTRIS") ? "INNTRIS" : "NONE",
          reason_codes: outcome.reason_codes,
          settlement_invoked: outcome.settlement_invoked,
          resource_served: outcome.resource_served,
        });

        // Recorded rather than asserted: the point of the matrix is to show
        // which defaults change the answer, so a configuration that fails is
        // evidence, not a broken test.
        expect(typeof rejected).toBe("boolean");
      });
    }
  }

  it("F-8: an unreachable facilitator on a request that Inntris would reject anyway", async () => {
    const context = await securityContext({ reconciliation: true });
    const unreachable = new FakeFacilitator("custom", {
      verify: () => {
        throw new Error("ETIMEDOUT contacting facilitator");
      },
    });
    const server = new GuardedResourceServer(context, unreachable);

    // The payee is mutated, so Inntris would refuse this at settlement. The
    // documented order sends it to the facilitator first.
    const outcome = await server
      .access({
        authorisationInput: honestInput,
        settlementInput: withRequirements({ payTo: "0x00000000000000000000000000000000000000ff" }),
        payload: paymentPayload({}),
        executionRef: "d6-f8",
      })
      .then((result) => ({ threw: false as const, result }))
      .catch((error: unknown) => ({ threw: true as const, error: error as Error }));

    // Fails closed, but by exception rather than by decision: the guard never
    // sees the request, so there is no reason code and no recorded rejection.
    expect(outcome.threw).toBe(true);
    expect(unreachable.settleCalls).toHaveLength(0);
    expect(server.served).toBe(0);

    recordEvidence({
      id: "D6:F8-facilitator-unreachable",
      deliverable: "D6",
      attack:
        "F-8. Facilitator times out on a request carrying a mutated payee that Inntris would have rejected",
      status: "KNOWN_GAP",
      expectation:
        "A request Inntris can reject on its own should not depend on a third party being reachable, and its refusal should carry a reason code.",
      observed:
        "The facilitator call raised before the guard was consulted. No settlement occurred and the resource was withheld, so the composite fails closed — but the failure surfaces as a transport exception with no Inntris reason code, no verdict and no recorded rejection. The same request rejects cleanly with ACTION_HASH_MISMATCH when the facilitator is reachable, which means availability of a third party determines whether a refusal is attributable.",
      enforcement: "NONE",
      reason_codes: [],
      settlement_invoked: false,
      resource_served: false,
      notes:
        "Ordering consequence of binding checks running POST_VERIFY. See the D3 Ordering column.",
    });
  });
});
