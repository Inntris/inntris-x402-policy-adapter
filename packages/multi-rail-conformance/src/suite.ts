import {
  InntrisActionV1Schema,
  InntrisDecisionV1Schema,
  type Clock,
  type DecisionProvider,
  type InntrisActionV1,
  type InntrisDecisionV1,
  type KeyRegistry,
  type Rail,
} from "@inntris/decision-core";
import { verifyDecision, type VerificationResult } from "@inntris/decision-verifier";

export const REQUIRED_CONFORMANCE_RAILS = ["x402", "ap2", "evm", "card", "mcp"] as const;

export interface MultiRailConformanceCase {
  rail: Rail;
  action: InntrisActionV1;
  mutatedAction: InntrisActionV1;
}

export interface MultiRailConformanceOutcome {
  rail: Rail;
  decision: InntrisDecisionV1;
  verification: VerificationResult;
  mutationVerification: VerificationResult;
}

export interface MultiRailConformanceReport {
  passed: true;
  policy_hash: string;
  policy_version: string;
  signing_key_id: string;
  outcomes: MultiRailConformanceOutcome[];
}

export interface MultiRailConformanceOptions {
  cases: MultiRailConformanceCase[];
  provider: DecisionProvider;
  keyRegistry: KeyRegistry;
  expectedPolicyVersion: string;
  clock: Clock;
}

export class MultiRailConformanceError extends Error {
  override readonly name = "MultiRailConformanceError";
}

function fail(message: string): never {
  throw new MultiRailConformanceError(message);
}

export async function runMultiRailConformance(
  options: MultiRailConformanceOptions,
): Promise<MultiRailConformanceReport> {
  const rails = options.cases.map((entry) => entry.rail);
  if (
    options.cases.length !== REQUIRED_CONFORMANCE_RAILS.length ||
    REQUIRED_CONFORMANCE_RAILS.some((rail) => rails.filter((entry) => entry === rail).length !== 1)
  ) {
    return fail("Conformance requires exactly one x402, AP2, EVM, card and MCP case");
  }

  const outcomes: MultiRailConformanceOutcome[] = [];
  for (const entry of options.cases) {
    const action = InntrisActionV1Schema.parse(entry.action);
    const mutatedAction = InntrisActionV1Schema.parse(entry.mutatedAction);
    if (action.rail !== entry.rail || mutatedAction.rail !== entry.rail) {
      return fail(`The ${entry.rail} case contains an action for another rail`);
    }

    const decision = InntrisDecisionV1Schema.parse(await options.provider.evaluate(action));
    const verification = verifyDecision({
      decision,
      action,
      keyRegistry: options.keyRegistry,
      at: options.clock.now(),
      expectedPolicyVersion: options.expectedPolicyVersion,
    });
    if (!verification.valid || decision.verdict !== "ALLOW") {
      return fail(`${entry.rail} did not produce a valid ALLOW decision`);
    }

    const mutationVerification = verifyDecision({
      decision,
      action: mutatedAction,
      keyRegistry: options.keyRegistry,
      at: options.clock.now(),
      expectedPolicyVersion: options.expectedPolicyVersion,
    });
    if (
      mutationVerification.valid ||
      !mutationVerification.reason_codes.includes("ACTION_HASH_MISMATCH")
    ) {
      return fail(`${entry.rail} did not invalidate its exact action mutation`);
    }
    outcomes.push({ rail: entry.rail, decision, verification, mutationVerification });
  }

  const first = outcomes[0]?.decision;
  if (first === undefined) {
    return fail("Conformance produced no decisions");
  }
  const topLevelShape = JSON.stringify(Object.keys(first).sort());
  for (const outcome of outcomes) {
    if (
      outcome.decision.version !== "inntris-decision-v1" ||
      outcome.decision.policy.policy_hash !== first.policy.policy_hash ||
      outcome.decision.policy.policy_version !== first.policy.policy_version ||
      outcome.decision.signing.key_id !== first.signing.key_id ||
      outcome.decision.signing.alg !== "Ed25519" ||
      outcome.decision.protocol_reference.type !== outcome.rail ||
      JSON.stringify(Object.keys(outcome.decision).sort()) !== topLevelShape
    ) {
      return fail("Rail outcomes did not preserve one shared Decision Envelope contract");
    }
  }

  return {
    passed: true,
    policy_hash: first.policy.policy_hash,
    policy_version: first.policy.policy_version,
    signing_key_id: first.signing.key_id,
    outcomes,
  };
}
