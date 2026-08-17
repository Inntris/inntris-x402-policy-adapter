import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import {
  buildKeyRegistryEntry,
  createPublicDemoSigner,
  type Clock,
  type InntrisDecisionV1,
  type KeyRegistry,
} from "@inntris/decision-core";
import {
  InMemoryExecutionReconciliationStore,
  type ExecutionReconciliationStore,
} from "@inntris/execution-reconciliation";
import {
  InMemorySpendState,
  LocalPolicyDecisionProvider,
  parsePolicyText,
  type SpendState,
} from "@inntris/policy-engine";
import {
  InntrisGuardError,
  InntrisX402Guard,
  X402BindingError,
  type PaymentPayload,
  type PaymentRequirements,
  type X402SettlementInput,
} from "@inntris/x402-adapter";

import type { RejectionLayer, RunOutcome } from "./evidence.js";

export class MutableClock implements Clock {
  constructor(private value: Date = new Date("2026-07-29T12:00:00.000Z")) {}

  now(): Date {
    return new Date(this.value);
  }

  advance(milliseconds: number): void {
    this.value = new Date(this.value.getTime() + milliseconds);
  }
}

/**
 * The quoted requirements a well-behaved resource server publishes in its 402
 * challenge. Every attack is expressed as a deviation from these values
 * somewhere in the authorise -> verify -> settle sequence.
 */
export const honestRequirements: PaymentRequirements = {
  scheme: "exact",
  network: "eip155:8453",
  asset: "USDC",
  amount: "4500000",
  payTo: "0x0000000000000000000000000000000000000001",
  maxTimeoutSeconds: 60,
  extra: {},
};

export const honestInput: X402SettlementInput = {
  paymentRequirements: honestRequirements,
  resource: "https://example.test/research",
  principalId: "org_demo",
  agentId: "agent_research_01",
  purpose: "research_api",
  assetDecimals: 6,
};

export function withRequirements(
  overrides: Partial<PaymentRequirements>,
  base: X402SettlementInput = honestInput,
): X402SettlementInput {
  return {
    ...base,
    paymentRequirements: { ...base.paymentRequirements, ...overrides },
  };
}

/**
 * Builds an x402 v2 payment payload. `accepted` mirrors the quoted
 * requirements unless a caller deliberately diverges them, and the inner
 * EIP-3009 authorisation is the value the payer actually signs.
 */
export function paymentPayload(options: {
  accepted?: PaymentRequirements;
  to?: string;
  value?: string;
  from?: string;
  resourceUrl?: string;
  validBefore?: string;
  nonce?: string;
  signature?: string;
}): PaymentPayload {
  const accepted = options.accepted ?? honestRequirements;
  return {
    x402Version: 2,
    resource: {
      url: options.resourceUrl ?? honestInput.resource,
      description: "Inntris security review payment",
      mimeType: "application/json",
    },
    accepted,
    payload: {
      signature: options.signature ?? `0x${"11".repeat(65)}`,
      authorization: {
        from: options.from ?? "0x0000000000000000000000000000000000000002",
        to: options.to ?? accepted.payTo,
        value: options.value ?? accepted.amount,
        validAfter: "0",
        validBefore: options.validBefore ?? "99999999999",
        nonce: options.nonce ?? `0x${"22".repeat(32)}`,
      },
    },
  };
}

/** Reads the inner EIP-3009 authorisation, which `@x402/core` types as opaque. */
export function innerAuthorization(payload: PaymentPayload): Record<string, string> {
  return (payload as unknown as { payload: { authorization: Record<string, string> } }).payload
    .authorization;
}

export interface SecurityContext {
  clock: MutableClock;
  provider: LocalPolicyDecisionProvider;
  guard: InntrisX402Guard;
  keyRegistry: KeyRegistry;
  reconciliationStore: ExecutionReconciliationStore | undefined;
}

export interface SecurityContextOptions {
  clock?: MutableClock;
  /** Defaults to false, matching the guard's own default. */
  reconciliation?: boolean;
  classifySettlementError?: (error: unknown) => "failed_final" | "outcome_unknown";
  /** Omit to leave the guard's policy-version pin unset, as a caller may. */
  expectedPolicyVersion?: string | undefined;
  policyPath?: string;
  spendState?: SpendState;
}

export async function securityContext(
  options: SecurityContextOptions = {},
): Promise<SecurityContext> {
  const clock = options.clock ?? new MutableClock();
  const policy = parsePolicyText(
    await readFile(resolve(options.policyPath ?? "policies/demo-x402-policy.yml"), "utf8"),
  );
  const signer = createPublicDemoSigner();
  const keyRegistry: KeyRegistry = {
    version: "inntris-key-registry-v1",
    keys: [buildKeyRegistryEntry(signer, { notBefore: new Date("2026-01-01T00:00:00.000Z") })],
  };
  const provider = new LocalPolicyDecisionProvider({
    policy,
    signer,
    clock,
    ...(options.spendState === undefined ? {} : { spendState: options.spendState }),
  });
  const reconciliationStore =
    options.reconciliation === true ? new InMemoryExecutionReconciliationStore() : undefined;
  const guard = new InntrisX402Guard({
    provider,
    keyRegistry,
    clock,
    expectedPolicyVersion: "expectedPolicyVersion" in options ? options.expectedPolicyVersion : "1",
    ...(reconciliationStore === undefined ? {} : { reconciliationStore }),
    ...(options.classifySettlementError === undefined
      ? {}
      : { classifySettlementError: options.classifySettlementError }),
  });
  return { clock, provider, guard, keyRegistry, reconciliationStore };
}

export { InMemorySpendState };

export type VerifyOutcome = { isValid: true } | { isValid: false; invalidReason: string };
export type SettleOutcome =
  { success: true; transaction: string } | { success: false; errorReason: string };

export interface FacilitatorBehaviour {
  verify?: (payload: PaymentPayload, requirements: PaymentRequirements) => VerifyOutcome;
  settle?: (payload: PaymentPayload, requirements: PaymentRequirements) => SettleOutcome;
}

/**
 * A deterministic stand-in for an x402 facilitator, modelling the two answers
 * a real one gives without reaching the network.
 */
export class FakeFacilitator {
  readonly verifyCalls: { payload: PaymentPayload; requirements: PaymentRequirements }[] = [];
  readonly settleCalls: { payload: PaymentPayload; requirements: PaymentRequirements }[] = [];

  constructor(
    readonly label: "compliant" | "permissive" | "custom",
    private readonly behaviour: FacilitatorBehaviour = {},
  ) {}

  verify(payload: PaymentPayload, requirements: PaymentRequirements): VerifyOutcome {
    this.verifyCalls.push({ payload, requirements });
    return this.behaviour.verify?.(payload, requirements) ?? { isValid: true };
  }

  settle(payload: PaymentPayload, requirements: PaymentRequirements): SettleOutcome {
    this.settleCalls.push({ payload, requirements });
    return this.behaviour.settle?.(payload, requirements) ?? { success: true, transaction: "0xtx" };
  }
}

/**
 * A facilitator that follows the x402 `exact` scheme rules: it settles only a
 * payment whose signed authorisation actually pays the quoted recipient the
 * quoted amount, within its validity window.
 */
export function compliantFacilitator(behaviour: FacilitatorBehaviour = {}): FakeFacilitator {
  return new FakeFacilitator("compliant", {
    verify: (payload, requirements) => {
      const authorization = innerAuthorization(payload);
      if (authorization.to?.toLowerCase() !== requirements.payTo.toLowerCase()) {
        return { isValid: false, invalidReason: "invalid_exact_evm_payload_recipient_mismatch" };
      }
      if (authorization.value !== requirements.amount) {
        return { isValid: false, invalidReason: "invalid_exact_evm_payload_value_mismatch" };
      }
      return { isValid: true };
    },
    ...behaviour,
  });
}

/**
 * A facilitator that approves everything. Running the matrix against it
 * isolates what Inntris enforces on its own from what the composite enforces,
 * which is the only honest measure of the adapter's independent value: the
 * reference study found rule violations in every facilitator it evaluated, so
 * a check Inntris does not own is a check Inntris cannot rely on.
 */
export function permissiveFacilitator(): FakeFacilitator {
  return new FakeFacilitator("permissive", {
    verify: () => ({ isValid: true }),
    settle: () => ({ success: true, transaction: "0xpermissive" }),
  });
}

export class SettlementFailure extends Error {
  override readonly name = "SettlementFailure";

  constructor(readonly reason: string) {
    super(`Settlement failed: ${reason}`);
  }
}

export interface AccessRequest {
  authorisationInput: X402SettlementInput;
  /** Defaults to the authorisation input; differ them to model a post-authorisation swap. */
  settlementInput?: X402SettlementInput;
  payload: PaymentPayload;
  executionRef: string;
  decision?: InntrisDecisionV1;
  /**
   * Models an integration that settles without a pre-flight verification.
   * Defaults to false, matching the order the documentation prescribes.
   */
  skipVerification?: boolean;
}

/**
 * A minimal x402-protected resource server wired in the documented order:
 * authorise under policy, ask the facilitator to verify, settle behind the
 * guard, then release the resource. Every rejection is attributed to the
 * component that produced it and to the layer at which it occurred, derived
 * from the observed call sequence rather than from where the check is supposed
 * to live.
 */
export class GuardedResourceServer {
  served = 0;

  constructor(
    private readonly context: SecurityContext,
    readonly facilitator: FakeFacilitator,
  ) {}

  async access(request: AccessRequest): Promise<RunOutcome> {
    const settlementInput = request.settlementInput ?? request.authorisationInput;
    const outcome = (
      partial: Omit<RunOutcome, "verify_calls" | "resource_served"> & { resource_served?: boolean },
    ): RunOutcome => ({
      ...partial,
      verify_calls: this.facilitator.verifyCalls.length,
      resource_served: partial.resource_served ?? false,
    });

    const inntrisLayer = (): RejectionLayer =>
      this.facilitator.verifyCalls.length === 0 ? "INNTRIS_PREFLIGHT" : "INNTRIS_POST_VERIFY";

    let decision = request.decision;
    if (decision === undefined) {
      try {
        decision = await this.context.guard.authorise(request.authorisationInput);
      } catch (error) {
        return outcome({
          rejected: true,
          layer: inntrisLayer(),
          component: "inntris-adapter",
          detail:
            error instanceof InntrisGuardError
              ? `InntrisGuardError: ${error.reasonCodes.join(", ")}`
              : error instanceof X402BindingError
                ? `X402BindingError: ${error.message}`
                : `${(error as Error).name}: ${(error as Error).message}`,
          reason_codes: error instanceof InntrisGuardError ? error.reasonCodes : [],
          settlement_invoked: false,
        });
      }
    }

    if (decision.verdict !== "ALLOW") {
      return outcome({
        rejected: true,
        layer: inntrisLayer(),
        component: "inntris-policy",
        detail: `verdict ${decision.verdict}`,
        reason_codes: decision.reason_codes,
        settlement_invoked: false,
      });
    }

    if (request.skipVerification !== true) {
      const verification = this.facilitator.verify(
        request.payload,
        settlementInput.paymentRequirements,
      );
      if (!verification.isValid) {
        return outcome({
          rejected: true,
          layer: "FACILITATOR_VERIFY",
          component: `facilitator:${this.facilitator.label}`,
          detail: verification.invalidReason,
          reason_codes: [],
          settlement_invoked: false,
        });
      }
    }

    let executorInvoked = false;
    try {
      const transaction = await this.context.guard.settleIfAuthorised(
        settlementInput,
        decision,
        request.executionRef,
        async () => {
          executorInvoked = true;
          const settled = this.facilitator.settle(
            request.payload,
            settlementInput.paymentRequirements,
          );
          if (!settled.success) {
            throw new SettlementFailure(settled.errorReason);
          }
          return settled.transaction;
        },
      );
      this.served += 1;
      return outcome({
        rejected: false,
        layer: "NONE",
        component: "none",
        detail: `resource released, transaction ${transaction}`,
        reason_codes: [],
        settlement_invoked: true,
        resource_served: true,
      });
    } catch (error) {
      const reasonCodes = error instanceof InntrisGuardError ? error.reasonCodes : [];
      return outcome({
        rejected: true,
        // The executor having run is what distinguishes a settlement-side
        // failure from a guard check that fired before any money moved.
        layer: executorInvoked ? "FACILITATOR_SETTLE" : inntrisLayer(),
        component: executorInvoked ? `facilitator:${this.facilitator.label}` : "inntris-guard",
        detail:
          error instanceof InntrisGuardError
            ? `InntrisGuardError: ${error.reasonCodes.join(", ")}`
            : `${(error as Error).name}: ${(error as Error).message}`,
        reason_codes: reasonCodes,
        settlement_invoked: executorInvoked,
      });
    }
  }
}

/**
 * Runs one attack twice, against a rule-following facilitator and against one
 * that approves everything, and reports who actually enforced the rule.
 */
export async function runBothFacilitators(input: {
  build: (facilitator: FakeFacilitator) => Promise<{
    server: GuardedResourceServer;
    run: (server: GuardedResourceServer) => Promise<RunOutcome>;
  }>;
}): Promise<{ compliant: RunOutcome; permissive: RunOutcome }> {
  const compliantHarness = await input.build(compliantFacilitator());
  const compliant = await compliantHarness.run(compliantHarness.server);
  const permissiveHarness = await input.build(permissiveFacilitator());
  const permissive = await permissiveHarness.run(permissiveHarness.server);
  return { compliant, permissive };
}

/**
 * Ownership follows from the permissive run: if the rule still holds when the
 * facilitator approves everything, Inntris enforced it. If it does not, the
 * compliant facilitator was the only thing standing in the way.
 */
export function enforcementOwner(
  compliant: RunOutcome,
  permissive: RunOutcome,
): "INNTRIS" | "FACILITATOR" | "NONE" {
  if (permissive.rejected && permissive.layer.startsWith("INNTRIS")) {
    return "INNTRIS";
  }
  if (compliant.rejected && !permissive.rejected) {
    return "FACILITATOR";
  }
  if (!compliant.rejected && !permissive.rejected) {
    return "NONE";
  }
  return permissive.layer.startsWith("FACILITATOR") ? "FACILITATOR" : "NONE";
}
