import { afterAll, describe, expect, it } from "vitest";

import {
  compliantFacilitator,
  enforcementOwner,
  FakeFacilitator,
  GuardedResourceServer,
  honestInput,
  honestRequirements,
  paymentPayload,
  permissiveFacilitator,
  securityContext,
  withRequirements,
  type SecurityContextOptions,
} from "./harness.js";
import { flushEvidence, recordEvidence, type RunOutcome } from "./evidence.js";

const ATTACKER_PAYEE = "0x00000000000000000000000000000000000000ff";

afterAll(async () => {
  await flushEvidence("d1-attack-matrix");
});

/** Builds a fresh, isolated server for one run against one facilitator. */
async function server(
  facilitator: FakeFacilitator,
  options: SecurityContextOptions = {},
): Promise<GuardedResourceServer> {
  return new GuardedResourceServer(await securityContext(options), facilitator);
}

function describeRun(outcome: RunOutcome): string {
  return outcome.rejected
    ? `rejected at ${outcome.layer} by ${outcome.component} (${outcome.detail})`
    : `NOT REJECTED: ${outcome.detail}`;
}

/**
 * The D1 oracle. Every case is run twice — once against a facilitator that
 * follows the scheme rules, once against one that approves everything — and
 * the rule's owner is derived from the pair rather than from the composite.
 */
async function attributed(input: {
  id: string;
  attack: string;
  expectation: string;
  run: (server: GuardedResourceServer) => Promise<RunOutcome>;
  /** Set when the permissive stand-in cannot express the attack's premise. */
  permissiveVariant?: { notExpressible: string } | { facilitator: () => FakeFacilitator };
  compliantFacilitatorOverride?: () => FakeFacilitator;
  contextOptions?: SecurityContextOptions;
  notes?: string;
  /**
   * Forces the recorded status when the derived one would be misleading — a
   * case can withhold the resource and still leave a gap worth recording.
   */
  statusOverride?: "PASS" | "BORROWED" | "KNOWN_GAP" | "NOT_TESTED";
  /**
   * Set when the attack premise is a facilitator failure and the measured
   * property is Inntris's containment of it, which the rejection layer alone
   * would misattribute to the facilitator.
   */
  enforcementOverride?: "INNTRIS_CONTAINMENT" | "NONE";
}): Promise<{ compliant: RunOutcome; permissive?: RunOutcome }> {
  const options = input.contextOptions ?? {};
  const compliant = await input.run(
    await server((input.compliantFacilitatorOverride ?? compliantFacilitator)(), options),
  );

  const variant = input.permissiveVariant;
  if (variant !== undefined && "notExpressible" in variant) {
    recordEvidence({
      id: input.id,
      deliverable: "D1",
      attack: input.attack,
      status: input.statusOverride ?? (compliant.rejected ? "PASS" : "KNOWN_GAP"),
      expectation: input.expectation,
      observed: `compliant facilitator: ${describeRun(compliant)}`,
      compliant,
      permissive: { not_expressible: variant.notExpressible },
      enforcement:
        input.enforcementOverride ??
        (compliant.layer.startsWith("INNTRIS") ? "INNTRIS" : "FACILITATOR"),
      reason_codes: compliant.reason_codes,
      settlement_invoked: compliant.settlement_invoked,
      resource_served: compliant.resource_served,
      ...(input.notes === undefined ? {} : { notes: input.notes }),
    });
    return { compliant };
  }

  const permissive = await input.run(
    await server(variant === undefined ? permissiveFacilitator() : variant.facilitator(), options),
  );
  const owner = enforcementOwner(compliant, permissive);
  const status =
    input.statusOverride ??
    (owner === "INNTRIS" ? "PASS" : owner === "FACILITATOR" ? "BORROWED" : "KNOWN_GAP");

  recordEvidence({
    id: input.id,
    deliverable: "D1",
    attack: input.attack,
    status,
    expectation: input.expectation,
    observed: `compliant facilitator: ${describeRun(compliant)}. permissive facilitator: ${describeRun(permissive)}.`,
    compliant,
    permissive,
    enforcement: input.enforcementOverride ?? owner,
    reason_codes: permissive.rejected ? permissive.reason_codes : compliant.reason_codes,
    settlement_invoked: permissive.settlement_invoked,
    resource_served: permissive.resource_served,
    ...(input.notes === undefined ? {} : { notes: input.notes }),
  });
  return { compliant, permissive };
}

/**
 * A substitution is attacked from both directions: asked for directly, which
 * organisational policy must refuse, and swapped in after a legitimate
 * authorisation, which the settlement binding must refuse.
 */
async function substitutionAttack(input: {
  id: string;
  attack: string;
  substituted: Partial<typeof honestRequirements>;
  expectedPolicyReason: string;
}): Promise<void> {
  const direct = await attributed({
    id: `${input.id}a`,
    attack: `${input.attack} — requested directly`,
    expectation: `Organisational policy refuses the substituted value with ${input.expectedPolicyReason}, without consulting a facilitator.`,
    run: async (resourceServer) =>
      resourceServer.access({
        authorisationInput: withRequirements(input.substituted),
        payload: paymentPayload({
          accepted: { ...honestRequirements, ...input.substituted },
        }),
        executionRef: `execution-${input.id}-direct`,
      }),
  });
  expect(direct.compliant.rejected).toBe(true);
  expect(direct.compliant.reason_codes).toContain(input.expectedPolicyReason);
  expect(direct.compliant.layer).toBe("INNTRIS_PREFLIGHT");
  expect(direct.permissive?.layer).toBe("INNTRIS_PREFLIGHT");

  const swap = await attributed({
    id: `${input.id}b`,
    attack: `${input.attack} — swapped in after a legitimate authorisation`,
    expectation:
      "The guard refuses to settle an action that differs from the authorised one, without relying on the facilitator to notice.",
    run: async (resourceServer) =>
      resourceServer.access({
        authorisationInput: honestInput,
        settlementInput: withRequirements(input.substituted),
        payload: paymentPayload({}),
        executionRef: `execution-${input.id}-swap`,
      }),
    notes:
      "Under the documented order the facilitator sees the swapped requirements first, so the compliant run attributes the rejection to FACILITATOR_VERIFY. The permissive run shows the guard rejecting the same swap independently.",
  });
  expect(swap.permissive?.rejected).toBe(true);
  expect(swap.permissive?.layer).toBe("INNTRIS_POST_VERIFY");
  expect(swap.permissive?.settlement_invoked).toBe(false);
}

describe("A1 recipient substitution", () => {
  it("is refused by Inntris independently of the facilitator", async () => {
    await substitutionAttack({
      id: "A1",
      attack: "Recipient substitution (payTo redirected to an attacker address)",
      substituted: { payTo: ATTACKER_PAYEE },
      expectedPolicyReason: "PAYEE_NOT_ALLOWED",
    });
  });
});

describe("A2 asset substitution", () => {
  it("is refused by Inntris independently of the facilitator", async () => {
    await substitutionAttack({
      id: "A2",
      attack: "Asset substitution (settlement asset changed to an unlisted token)",
      substituted: { asset: "DAI" },
      expectedPolicyReason: "ASSET_NOT_ALLOWED",
    });
  });
});

describe("A3 amount substitution", () => {
  it("is refused by Inntris independently of the facilitator", async () => {
    await substitutionAttack({
      id: "A3",
      attack: "Amount substitution (settlement amount raised above the quoted price)",
      substituted: { amount: "150000000" },
      expectedPolicyReason: "AMOUNT_EXCEEDS_TRANSACTION_LIMIT",
    });
  });

  // F-1. Marked `fails` so it passes while the gap is open and breaks loudly
  // the moment precision stops being caller-supplied.
  it.fails("F-1: caller-declared assetDecimals rescales the amount policy sees", async () => {
    const understated = { ...withRequirements({ amount: "150000000" }), assetDecimals: 9 };
    const outcome = await attributed({
      id: "A3-F1",
      attack:
        "Amount substitution via declared asset precision (assetDecimals supplied by the caller)",
      expectation:
        "The decimal amount policy evaluates should be derived from the asset, so an atomic amount cannot be rescaled below a limit.",
      run: async (resourceServer) =>
        resourceServer.access({
          authorisationInput: understated,
          payload: paymentPayload({
            accepted: { ...honestRequirements, amount: "150000000" },
          }),
          executionRef: "execution-F1",
        }),
      notes:
        "Atomic 150000000 is BLOCKed as 150.00 at assetDecimals=6 and ALLOWed as 0.15 at assetDecimals=9. Decision, action hash and requirements hash are mutually consistent in both cases, so no verifier downstream can detect the rescaling.",
    });

    expect(outcome.permissive?.resource_served).toBe(true);
    // The secure expectation, which currently does not hold.
    expect(outcome.compliant.rejected).toBe(true);
  });
});

describe("A4 network substitution", () => {
  it("is refused by Inntris independently of the facilitator", async () => {
    await substitutionAttack({
      id: "A4",
      attack: "Network substitution (settlement moved to a different chain)",
      substituted: { network: "eip155:84532" },
      expectedPolicyReason: "NETWORK_NOT_ALLOWED",
    });
  });
});

describe("A5 expired authorisation", () => {
  it("is refused by Inntris independently of the facilitator", async () => {
    const outcome = await attributed({
      id: "A5",
      attack: "Expired authorisation (decision presented after its expiry)",
      expectation:
        "An expired decision must not settle, and the refusal must not depend on the facilitator.",
      run: async (resourceServer) => {
        const context = await securityContext();
        const decision = await context.guard.authorise(honestInput);
        // The demo policy issues a 60 second decision TTL.
        context.clock.advance(61_000);
        const scoped = new GuardedResourceServer(context, resourceServer.facilitator);
        return scoped.access({
          authorisationInput: honestInput,
          payload: paymentPayload({}),
          executionRef: "execution-A5",
          decision,
        });
      },
    });

    expect(outcome.compliant.reason_codes).toContain("DECISION_EXPIRED");
    expect(outcome.permissive?.reason_codes).toContain("DECISION_EXPIRED");
    expect(outcome.permissive?.layer).toBe("INNTRIS_POST_VERIFY");
    expect(outcome.permissive?.settlement_invoked).toBe(false);
  });
});

describe("A6 nonce and replay", () => {
  it("refuses a second execution reference independently of the facilitator", async () => {
    const outcome = await attributed({
      id: "A6",
      attack: "Nonce replay (one decision presented for a second, different execution)",
      expectation:
        "A consumed decision must not settle again under a new execution reference, without relying on facilitator idempotency.",
      run: async (resourceServer) => {
        const context = await securityContext({ reconciliation: true });
        const scoped = new GuardedResourceServer(context, resourceServer.facilitator);
        const decision = await context.guard.authorise(honestInput);
        await scoped.access({
          authorisationInput: honestInput,
          payload: paymentPayload({}),
          executionRef: "execution-A6-1",
          decision,
        });
        return scoped.access({
          authorisationInput: honestInput,
          payload: paymentPayload({}),
          executionRef: "execution-A6-2",
          decision,
        });
      },
    });

    expect(outcome.permissive?.reason_codes).toContain("NONCE_ALREADY_CONSUMED");
    expect(outcome.permissive?.layer).toBe("INNTRIS_POST_VERIFY");
  });

  it("refuses a reused execution reference when reconciliation is configured", async () => {
    const outcome = await attributed({
      id: "A6-recon",
      attack: "Settlement replay with the same execution reference, reconciliation configured",
      expectation:
        "A completed settlement must not be re-executed when the attacker reuses the execution reference.",
      run: async (resourceServer) => {
        const context = await securityContext({ reconciliation: true });
        const scoped = new GuardedResourceServer(context, resourceServer.facilitator);
        const decision = await context.guard.authorise(honestInput);
        await scoped.access({
          authorisationInput: honestInput,
          payload: paymentPayload({}),
          executionRef: "execution-A6-recon",
          decision,
        });
        return scoped.access({
          authorisationInput: honestInput,
          payload: paymentPayload({}),
          executionRef: "execution-A6-recon",
          decision,
        });
      },
    });

    expect(outcome.permissive?.reason_codes).toContain("EXECUTION_ALREADY_COMPLETED");
  });

  // F-2.
  it.fails("F-2: without a reconciliation store an identical retry settles again", async () => {
    const outcome = await attributed({
      id: "A6-F2",
      attack: "Settlement replay with no execution reconciliation store, the guard's default",
      expectation:
        "Replaying a settled payment must never invoke the settlement executor a second time.",
      run: async (resourceServer) => {
        const context = await securityContext();
        const scoped = new GuardedResourceServer(context, resourceServer.facilitator);
        const decision = await context.guard.authorise(honestInput);
        await scoped.access({
          authorisationInput: honestInput,
          payload: paymentPayload({}),
          executionRef: "execution-F2",
          decision,
        });
        return scoped.access({
          authorisationInput: honestInput,
          payload: paymentPayload({}),
          executionRef: "execution-F2",
          decision,
        });
      },
      notes:
        "An idempotent nonce consumption is treated as success, and with reconciliationStore undefined nothing else stands between that answer and a second settlement.",
    });

    expect(outcome.permissive?.resource_served).toBe(true);
    // The secure expectation, which currently does not hold.
    expect(outcome.compliant.rejected).toBe(true);
  });
});

describe("A7 insufficient balance", () => {
  it("is enforced only by the facilitator", async () => {
    const outcome = await attributed({
      id: "A7",
      attack: "Insufficient balance (payer cannot fund the quoted amount)",
      expectation:
        "A payer without funds should not have the resource released. Inntris holds no balance state, so this is expected to be facilitator-owned; the run measures whether anything else stops it.",
      compliantFacilitatorOverride: () =>
        new FakeFacilitator("custom", {
          verify: () => ({ isValid: false, invalidReason: "insufficient_funds" }),
        }),
      run: async (resourceServer) =>
        resourceServer.access({
          authorisationInput: honestInput,
          payload: paymentPayload({}),
          executionRef: "execution-A7",
        }),
      notes:
        "Balance is not observable to the adapter. Recorded as BORROWED rather than PASS because no Inntris check contributes to it.",
    });

    expect(outcome.compliant.layer).toBe("FACILITATOR_VERIFY");
    expect(outcome.permissive?.resource_served).toBe(true);
  });

  it("records an unresolved operation when funds fail during settlement", async () => {
    const outcome = await attributed({
      id: "A7-late",
      attack: "Insufficient balance surfacing only when settlement is attempted",
      expectation:
        "A settlement that fails after being attempted must not release the resource and must leave an operator-visible unresolved record.",
      compliantFacilitatorOverride: () =>
        new FakeFacilitator("custom", {
          settle: () => ({ success: false, errorReason: "insufficient_funds" }),
        }),
      permissiveVariant: {
        notExpressible:
          "The permissive stand-in never fails settlement, so a settlement-time funding failure cannot be produced against it.",
      },
      contextOptions: { reconciliation: true },
      enforcementOverride: "INNTRIS_CONTAINMENT",
      run: async (resourceServer) =>
        resourceServer.access({
          authorisationInput: honestInput,
          payload: paymentPayload({}),
          executionRef: "execution-A7-late",
        }),
    });

    expect(outcome.compliant.layer).toBe("FACILITATOR_SETTLE");
    expect(outcome.compliant.resource_served).toBe(false);
    expect(outcome.compliant.reason_codes).toContain("EXECUTION_OUTCOME_UNKNOWN");
  });

  it("loses outcome bookkeeping entirely when no reconciliation store is configured", async () => {
    const outcome = await attributed({
      id: "A7-late-nostore",
      attack:
        "Settlement failure with no execution reconciliation store, the guard's default configuration",
      expectation:
        "A settlement failure should carry an Inntris reason code and leave a durable unresolved record regardless of configuration.",
      compliantFacilitatorOverride: () =>
        new FakeFacilitator("custom", {
          settle: () => ({ success: false, errorReason: "insufficient_funds" }),
        }),
      permissiveVariant: {
        notExpressible:
          "The permissive stand-in never fails settlement, so a settlement-time funding failure cannot be produced against it.",
      },
      run: async (resourceServer) =>
        resourceServer.access({
          authorisationInput: honestInput,
          payload: paymentPayload({}),
          executionRef: "execution-A7-late-nostore",
        }),
      notes:
        "Second face of F-2. With reconciliationStore undefined the raw executor error propagates uncaught out of settleIfAuthorised: no InntrisGuardError, no reason code, and no unresolved operation for an operator to reconcile. The caller is left to interpret a bare facilitator error.",
      statusOverride: "KNOWN_GAP",
      enforcementOverride: "NONE",
    });

    // Recorded as observed, not asserted as correct: the resource is still
    // withheld, but nothing durable records that a settlement was attempted.
    expect(outcome.compliant.layer).toBe("FACILITATOR_SETTLE");
    expect(outcome.compliant.resource_served).toBe(false);
    expect(outcome.compliant.reason_codes).toEqual([]);
    expect(outcome.compliant.detail).toContain("SettlementFailure");
  });
});

describe("A8 facilitator verify=true followed by settlement failure", () => {
  it("fails closed and refuses an automatic retry", async () => {
    const outcome = await attributed({
      id: "A8",
      attack: "Facilitator verifies the payment, then settlement fails or times out",
      expectation:
        "An unknown settlement outcome must not release the resource, must not retry automatically, and must leave a durable record.",
      compliantFacilitatorOverride: () =>
        new FakeFacilitator("custom", {
          settle: () => ({ success: false, errorReason: "settlement_timeout" }),
        }),
      permissiveVariant: {
        notExpressible:
          "The permissive stand-in always settles successfully, so the attack premise cannot be produced against it.",
      },
      run: async (resourceServer) => {
        const context = await securityContext({ reconciliation: true });
        const scoped = new GuardedResourceServer(context, resourceServer.facilitator);
        const decision = await context.guard.authorise(honestInput);
        await scoped.access({
          authorisationInput: honestInput,
          payload: paymentPayload({}),
          executionRef: "execution-A8",
          decision,
        });
        // The retry is the measured event: it must not reach the facilitator.
        return scoped.access({
          authorisationInput: honestInput,
          payload: paymentPayload({}),
          executionRef: "execution-A8",
          decision,
        });
      },
      enforcementOverride: "INNTRIS_CONTAINMENT",
    });

    expect(outcome.compliant.reason_codes).toContain("EXECUTION_OUTCOME_UNKNOWN");
    expect(outcome.compliant.layer).toBe("INNTRIS_POST_VERIFY");
    expect(outcome.compliant.settlement_invoked).toBe(false);
    expect(outcome.compliant.resource_served).toBe(false);
  });

  // F-3.
  it.fails(
    "F-3: the guard does not require facilitator verification before settlement",
    async () => {
      const outcome = await attributed({
        id: "A7-A8-F3",
        attack: "Settlement executed without a preceding facilitator verification",
        expectation:
          "The guard should make verify-before-settle structurally unavoidable, so an integration cannot settle an unverified payment.",
        compliantFacilitatorOverride: () =>
          new FakeFacilitator("custom", {
            verify: () => ({ isValid: false, invalidReason: "invalid_signature" }),
          }),
        run: async (resourceServer) =>
          resourceServer.access({
            authorisationInput: honestInput,
            payload: paymentPayload({}),
            executionRef: "execution-F3",
            skipVerification: true,
          }),
        notes:
          "settleIfAuthorised accepts an opaque executor and has no facilitator seam, so an integration that omits verification settles regardless. The facilitator here would have rejected the payment had it been asked.",
      });

      expect(outcome.compliant.verify_calls).toBe(0);
      expect(outcome.compliant.resource_served).toBe(true);
      // The secure expectation, which currently does not hold.
      expect(outcome.compliant.rejected).toBe(true);
    },
  );
});

describe("A9 repeated resource access after one payment", () => {
  it("serves once per authorisation independently of the facilitator", async () => {
    const outcome = await attributed({
      id: "A9",
      attack: "Repeated resource access using a single paid authorisation",
      expectation:
        "One authorisation must yield at most one settled access, without relying on the facilitator.",
      run: async (resourceServer) => {
        const context = await securityContext({ reconciliation: true });
        const scoped = new GuardedResourceServer(context, resourceServer.facilitator);
        const decision = await context.guard.authorise(honestInput);
        await scoped.access({
          authorisationInput: honestInput,
          payload: paymentPayload({}),
          executionRef: "execution-A9-1",
          decision,
        });
        const second = await scoped.access({
          authorisationInput: honestInput,
          payload: paymentPayload({}),
          executionRef: "execution-A9-2",
          decision,
        });
        expect(scoped.served).toBe(1);
        return second;
      },
    });

    expect(outcome.permissive?.reason_codes).toContain("NONCE_ALREADY_CONSUMED");
    expect(outcome.permissive?.layer).toBe("INNTRIS_POST_VERIFY");
  });
});

describe("A10 mismatched payment requirement versus signed payment", () => {
  it("refuses a payload bound to different requirements, before any facilitator call", async () => {
    const outcome = await attributed({
      id: "A10",
      attack: "Payment payload bound to different payment requirements than the ones charged",
      expectation:
        "A payload whose accepted requirements differ from the quoted requirements must be refused by Inntris before a facilitator is consulted.",
      run: async (resourceServer) =>
        resourceServer.access({
          authorisationInput: {
            ...honestInput,
            paymentPayload: paymentPayload({
              accepted: { ...honestRequirements, payTo: ATTACKER_PAYEE },
            }),
          },
          payload: paymentPayload({
            accepted: { ...honestRequirements, payTo: ATTACKER_PAYEE },
          }),
          executionRef: "execution-A10",
        }),
    });

    expect(outcome.compliant.layer).toBe("INNTRIS_PREFLIGHT");
    expect(outcome.compliant.detail).toContain("X402BindingError");
    expect(outcome.permissive?.layer).toBe("INNTRIS_PREFLIGHT");
  });

  it("refuses a payload introduced after a payload-free authorisation", async () => {
    const outcome = await attributed({
      id: "A10-late",
      attack: "Payment payload attached only after the decision was issued without one",
      expectation:
        "The settled action must be byte-identical to the authorised action, including the presence or absence of a payload binding.",
      run: async (resourceServer) => {
        const context = await securityContext();
        const scoped = new GuardedResourceServer(context, resourceServer.facilitator);
        const decision = await context.guard.authorise(honestInput);
        return scoped.access({
          authorisationInput: honestInput,
          settlementInput: { ...honestInput, paymentPayload: paymentPayload({}) },
          payload: paymentPayload({}),
          executionRef: "execution-A10-late",
          decision,
        });
      },
    });

    expect(outcome.permissive?.reason_codes).toContain("ACTION_HASH_MISMATCH");
    expect(outcome.permissive?.settlement_invoked).toBe(false);
  });

  // F-4.
  it.fails("F-4: the inner signed authorisation is bound but never cross-checked", async () => {
    const divergent = paymentPayload({ to: ATTACKER_PAYEE, value: "1" });
    const outcome = await attributed({
      id: "A10-F4",
      attack:
        "Signed EIP-3009 authorisation diverges from the accepted requirements it is presented with",
      expectation:
        "An Inntris ALLOW should attest that the payment actually signed pays the approved recipient the approved amount.",
      run: async (resourceServer) =>
        resourceServer.access({
          authorisationInput: { ...honestInput, paymentPayload: divergent },
          payload: divergent,
          executionRef: "execution-F4",
        }),
      notes:
        "Every policy field is derived from `accepted`; `payload` is bound only as an opaque hash. The archetype of a borrowed check: the compliant facilitator rejects it, the permissive one settles it, and no Inntris check participates.",
    });

    expect(outcome.compliant.layer).toBe("FACILITATOR_VERIFY");
    expect(outcome.permissive?.resource_served).toBe(true);
    // The secure expectation, which currently does not hold.
    expect(outcome.compliant.layer).toBe("INNTRIS_PREFLIGHT");
  });
});
