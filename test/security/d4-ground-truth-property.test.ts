import { afterAll, describe, expect, it } from "vitest";

import { honestInput, honestRequirements, securityContext } from "./harness.js";
import { flushEvidence, recordEvidence } from "./evidence.js";

afterAll(async () => {
  await flushEvidence("d4-ground-truth");
});

/**
 * The re-specified D4 property.
 *
 * The original property was "a policy-bearing mutation changes the decision or
 * is rejected". F-1 satisfies it — rescaling `assetDecimals` does change the
 * decision — so the property could never detect the bypass it was meant to
 * catch. It measured movement, not correctness.
 *
 * This property measures correctness against a ground truth the harness owns.
 * The true economic value of a payment is computed here, from a registry the
 * adapter has no access to and cannot influence, and the decision is required
 * to agree with it. Any divergence is a finding by construction, whatever the
 * adapter's internal consistency.
 */

/** Test-owned truth. Deliberately not read from the adapter or its inputs. */
const TRUE_ASSET_DECIMALS: Record<string, number> = {
  "eip155:8453|USDC": 6,
  "eip155:8453|DAI": 18,
  "eip155:1|USDC": 6,
  "eip155:84532|USDC": 6,
};

/**
 * The oracle uses exact scaled-integer arithmetic rather than the adapter's
 * decimal library. An instrument that shares a numeric implementation with the
 * thing it measures cannot detect a fault in that implementation.
 */
const SCALE = 18n;
const ONE = 10n ** SCALE;

/** Parses a canonical decimal string into an exact scaled integer. */
export function toScaled(value: string): bigint {
  const [whole = "0", fraction = ""] = value.split(".");
  const padded = fraction.padEnd(Number(SCALE), "0").slice(0, Number(SCALE));
  return BigInt(whole) * ONE + BigInt(padded === "" ? "0" : padded);
}

/** Renders a scaled integer back to a decimal string for reporting. */
export function fromScaled(value: bigint, places = 2): string {
  const whole = value / ONE;
  const fraction = (value % ONE).toString().padStart(Number(SCALE), "0").slice(0, places);
  return `${whole.toString()}.${fraction}`;
}

/** Policy limits, restated here so the oracle does not read them from the adapter. */
const PER_TRANSACTION_LIMIT = toScaled("100.00");
const REQUIRE_HUMAN_ABOVE = toScaled("75.00");

export function trueEconomicValue(network: string, asset: string, atomicAmount: string): bigint {
  const decimals = TRUE_ASSET_DECIMALS[`${network}|${asset}`];
  if (decimals === undefined) {
    throw new Error(`No ground truth for ${network}|${asset}; the oracle must not guess`);
  }
  // atomic * 10^(SCALE - decimals), exactly.
  return BigInt(atomicAmount) * 10n ** (SCALE - BigInt(decimals));
}

/** What a correct policy engine must return for a given true value. */
export function expectedVerdict(value: bigint): "ALLOW" | "REQUIRE_APPROVAL" | "BLOCK" {
  if (value > PER_TRANSACTION_LIMIT) return "BLOCK";
  if (value > REQUIRE_HUMAN_ABOVE) return "REQUIRE_APPROVAL";
  return "ALLOW";
}

export interface GroundTruthViolation {
  atomicAmount: string;
  declaredDecimals: number;
  trueValue: string;
  evaluatedAmount: string;
  expectedVerdict: string;
  actualVerdict: string;
}

describe("D4 ground-truth property (re-specified)", () => {
  it("the oracle rejects a case it has no ground truth for, rather than guessing", () => {
    expect(() => trueEconomicValue("eip155:8453", "MYSTERY", "1")).toThrow(/must not guess/);
  });

  it("detects F-1, which the original property could not", async () => {
    const context = await securityContext();
    const atomicAmount = "150000000";

    // Ground truth: 150000000 atomic units of 6-decimal USDC is 150.00, which
    // exceeds the per-transaction limit and must not be ALLOWed.
    const value = trueEconomicValue(
      honestRequirements.network,
      honestRequirements.asset,
      atomicAmount,
    );
    expect(fromScaled(value)).toBe("150.00");
    expect(expectedVerdict(value)).toBe("BLOCK");

    const decision = await context.guard.authorise({
      ...honestInput,
      paymentRequirements: { ...honestRequirements, amount: atomicAmount },
      assetDecimals: 9,
    });

    const violation: GroundTruthViolation = {
      atomicAmount,
      declaredDecimals: 9,
      trueValue: fromScaled(value),
      evaluatedAmount: decision.transaction.amount,
      expectedVerdict: expectedVerdict(value),
      actualVerdict: decision.verdict,
    };

    // The property that matters: the decision must agree with ground truth.
    const agrees =
      decision.verdict === expectedVerdict(value) &&
      toScaled(decision.transaction.amount) === value;
    expect(agrees).toBe(false); // currently violated — this is F-1

    recordEvidence({
      id: "D4:ground-truth-property",
      deliverable: "D4",
      attack: "Re-specified property — decision must agree with independently computed true value",
      status: "KNOWN_GAP",
      expectation:
        "For every mutation, the decision's evaluated amount and verdict must agree with the true economic value computed from an asset registry the adapter cannot influence.",
      observed: `The oracle is wired and detects F-1: ${JSON.stringify(violation)}. The original property returned zero silent mutations across 47 cases because it asked whether the decision moved, not whether it moved correctly.`,
      enforcement: "NONE",
      reason_codes: decision.reason_codes,
      settlement_invoked: false,
      resource_served: false,
      notes:
        "Instrument validated, not yet applied to the corpus. Per the unfreeze sequence the corpus is not re-run under this property until F-1 closes; at Stage 5 it replaces the original property in d4-mutation-corpus.test.ts.",
    });
  });

  it("agrees with the adapter when the declared precision is honest", async () => {
    const context = await securityContext();
    const value = trueEconomicValue(
      honestRequirements.network,
      honestRequirements.asset,
      "4500000",
    );
    const decision = await context.guard.authorise(honestInput);

    expect(fromScaled(value)).toBe("4.50");
    expect(decision.verdict).toBe(expectedVerdict(value));
    expect(toScaled(decision.transaction.amount)).toBe(value);

    recordEvidence({
      id: "D4:ground-truth-control",
      deliverable: "D4",
      attack: "Ground-truth oracle control — honest precision",
      status: "PASS",
      expectation:
        "The oracle must agree with the adapter whenever the declared precision matches the registry, or it would report false positives.",
      observed:
        "True value 4.50 from the registry; adapter evaluated 4.50 and returned ALLOW, which is the verdict the oracle requires. The oracle discriminates F-1 without flagging correct behaviour.",
      enforcement: "INNTRIS",
      reason_codes: decision.reason_codes,
      settlement_invoked: false,
      resource_served: false,
    });
  });
});
