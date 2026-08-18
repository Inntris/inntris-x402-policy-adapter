import { afterAll, describe, expect, it } from "vitest";

import {
  FakeFacilitator,
  GuardedResourceServer,
  honestInput,
  paymentPayload,
  securityContext,
} from "./harness.js";
import { flushEvidence, recordEvidence } from "./evidence.js";

afterAll(async () => {
  await flushEvidence("e-settlement-truthfulness");
});

/**
 * Group E of the review register — SR4 and the two server-side rules. The
 * question is whether "paid" means a confirmed chain state or a facilitator's
 * JSON. Every case here runs with a reconciliation store configured, which is
 * the adapter's strongest configuration.
 */
describe("E settlement truthfulness", () => {
  it("E2: settlement reported successful with no transaction identifier is accepted", async () => {
    const context = await securityContext({ reconciliation: true });
    const facilitator = new FakeFacilitator("custom", {
      // A facilitator that answers success while naming no transaction.
      settle: () => ({ success: true, transaction: "" }),
    });
    const server = new GuardedResourceServer(context, facilitator);

    const outcome = await server.access({
      authorisationInput: honestInput,
      payload: paymentPayload({}),
      executionRef: "e2-no-txid",
    });

    expect(outcome.rejected).toBe(false);
    expect(outcome.resource_served).toBe(true);
    const operations = await context.reconciliationStore!.listUnresolved();
    expect(operations).toHaveLength(0);

    recordEvidence({
      id: "E2:no-transaction-identifier",
      deliverable: "E",
      attack: "Facilitator reports settlement success without a transaction identifier",
      status: "KNOWN_GAP",
      expectation:
        "A settlement naming no transaction should be treated as unsettled and the resource withheld.",
      observed:
        "The resource was released and the operation was marked succeeded. settleIfAuthorised treats any executor return that does not throw as success (guard.ts:255-307) and never inspects the returned value, so the settlement executor's result is opaque to the guard. An empty transaction identifier is indistinguishable from a real one.",
      enforcement: "NONE",
      reason_codes: [],
      settlement_invoked: true,
      resource_served: true,
      notes: "SR4. Review register row E2.",
    });
  });

  it("E3: a transaction identifier that never settled on chain is accepted", async () => {
    const context = await securityContext({ reconciliation: true });
    const facilitator = new FakeFacilitator("custom", {
      // A plausible hash for a transaction that reverted, was dropped, or was
      // never broadcast. Nothing in the adapter can tell the difference.
      settle: () => ({ success: true, transaction: `0x${"de".repeat(32)}` }),
    });
    const server = new GuardedResourceServer(context, facilitator);

    const outcome = await server.access({
      authorisationInput: honestInput,
      payload: paymentPayload({}),
      executionRef: "e3-phantom-tx",
    });

    expect(outcome.rejected).toBe(false);
    expect(outcome.resource_served).toBe(true);

    recordEvidence({
      id: "E3:unconfirmed-transaction",
      deliverable: "E",
      attack:
        "Facilitator reports settlement success with a transaction that reverted, was dropped, or does not exist",
      status: "KNOWN_GAP",
      expectation:
        "Settlement should be confirmed independently against the chain at a stated depth before the resource is released.",
      observed:
        "The resource was released on the facilitator's word alone. The adapter contains no chain client, no RPC configuration and no confirmation-depth setting: grep across packages/ finds no provider, no eth_getTransactionReceipt equivalent, and no anchoring code. Inntris's notion of settled is the facilitator's JSON.",
      enforcement: "NONE",
      reason_codes: [],
      settlement_invoked: true,
      resource_served: true,
      notes:
        "SR4, the rule the review names as determining whether Inntris confirms or relays. Resolves the A7 severity condition: with no independent settleability check and no independent settlement confirmation, a permissive facilitator's success is accepted end to end.",
    });
  });

  it("E4: a settlement failure reverses no post-verification effect beyond withholding", async () => {
    const context = await securityContext({ reconciliation: true });
    const facilitator = new FakeFacilitator("custom", {
      settle: () => ({ success: false, errorReason: "reverted" }),
    });
    const server = new GuardedResourceServer(context, facilitator);

    const decision = await context.guard.authorise(honestInput);
    const outcome = await server.access({
      authorisationInput: honestInput,
      payload: paymentPayload({}),
      executionRef: "e4-rollback",
      decision,
    });

    // The decision's nonce is consumed before the executor runs and is not
    // released when settlement fails, so the authorisation is spent.
    const reconsume = await context.guard.consumeBeforeExecution(decision, "e4-rollback-retry");
    const operations = await context.reconciliationStore!.listUnresolved();

    expect(outcome.resource_served).toBe(false);
    expect(reconsume.success).toBe(false);
    expect(operations).toHaveLength(1);
    expect(operations[0]).toMatchObject({ status: "outcome_unknown" });

    recordEvidence({
      id: "E4:rollback",
      deliverable: "E",
      attack: "Post-verification effects when settlement fails",
      status: "PASS",
      expectation:
        "The request is treated as unpaid, the resource is withheld, and the failure is durably recorded.",
      observed:
        "The resource was withheld and the operation left unresolved as outcome_unknown for reconciliation. The consumed nonce is not returned, so the authorisation is spent and cannot be replayed — the payer must obtain a new decision. That is fail-closed, and it is the correct direction, but it is a withholding rather than a reversal: no compensating record is signed.",
      enforcement: "INNTRIS_CONTAINMENT",
      reason_codes: outcome.reason_codes,
      settlement_invoked: true,
      resource_served: false,
      notes:
        "Server-SR2. Conditional on a reconciliation store; see A7-late-nostore for the default.",
    });
  });
});
