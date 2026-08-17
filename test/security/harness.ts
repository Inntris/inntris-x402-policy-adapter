import { mkdir, writeFile } from "node:fs/promises";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

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
import { LocalPolicyDecisionProvider, parsePolicyText } from "@inntris/policy-engine";
import {
  InntrisGuardError,
  InntrisX402Guard,
  type PaymentPayload,
  type PaymentRequirements,
  type X402SettlementInput,
} from "@inntris/x402-adapter";

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
 * challenge. Every attack in this suite is expressed as a deviation from these
 * values somewhere in the authorise -> verify -> settle sequence.
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
      signature: `0x${"11".repeat(65)}`,
      authorization: {
        from: options.from ?? "0x0000000000000000000000000000000000000002",
        to: options.to ?? accepted.payTo,
        value: options.value ?? accepted.amount,
        validAfter: "0",
        validBefore: "99999999999",
        nonce: `0x${"22".repeat(32)}`,
      },
    },
  };
}

export interface SecurityContext {
  clock: MutableClock;
  provider: LocalPolicyDecisionProvider;
  guard: InntrisX402Guard;
  keyRegistry: KeyRegistry;
  reconciliationStore: ExecutionReconciliationStore | undefined;
}

export async function securityContext(
  options: {
    clock?: MutableClock;
    reconciliation?: boolean;
    classifySettlementError?: (error: unknown) => "failed_final" | "outcome_unknown";
  } = {},
): Promise<SecurityContext> {
  const clock = options.clock ?? new MutableClock();
  const policy = parsePolicyText(await readFile(resolve("policies/demo-x402-policy.yml"), "utf8"));
  const signer = createPublicDemoSigner();
  const keyRegistry: KeyRegistry = {
    version: "inntris-key-registry-v1",
    keys: [buildKeyRegistryEntry(signer, { notBefore: new Date("2026-01-01T00:00:00.000Z") })],
  };
  const provider = new LocalPolicyDecisionProvider({ policy, signer, clock });
  const reconciliationStore =
    options.reconciliation === true ? new InMemoryExecutionReconciliationStore() : undefined;
  const guard = new InntrisX402Guard({
    provider,
    keyRegistry,
    expectedPolicyVersion: "1",
    clock,
    ...(reconciliationStore === undefined ? {} : { reconciliationStore }),
    ...(options.classifySettlementError === undefined
      ? {}
      : { classifySettlementError: options.classifySettlementError }),
  });
  return { clock, provider, guard, keyRegistry, reconciliationStore };
}

export interface FacilitatorBehaviour {
  verify?: (payload: PaymentPayload, requirements: PaymentRequirements) => VerifyOutcome;
  settle?: (payload: PaymentPayload, requirements: PaymentRequirements) => SettleOutcome;
}

export type VerifyOutcome = { isValid: true } | { isValid: false; invalidReason: string };
export type SettleOutcome =
  | { success: true; transaction: string }
  | { success: false; errorReason: string; throws?: boolean };

/**
 * A deterministic stand-in for an x402 facilitator. It models the two answers
 * a real facilitator gives — a pre-flight verification and a settlement
 * outcome — without reaching the network, so settlement-boundary behaviour is
 * reproducible.
 */
export class FakeFacilitator {
  verifyCalls: { payload: PaymentPayload; requirements: PaymentRequirements }[] = [];
  settleCalls: { payload: PaymentPayload; requirements: PaymentRequirements }[] = [];

  constructor(private readonly behaviour: FacilitatorBehaviour = {}) {}

  /**
   * The honest default: a payment verifies only when the signed authorisation
   * actually pays the quoted recipient the quoted amount.
   */
  verify(payload: PaymentPayload, requirements: PaymentRequirements): VerifyOutcome {
    this.verifyCalls.push({ payload, requirements });
    if (this.behaviour.verify !== undefined) {
      return this.behaviour.verify(payload, requirements);
    }
    const authorization = (
      payload as unknown as { payload: { authorization: Record<string, string> } }
    ).payload.authorization;
    if (authorization.to?.toLowerCase() !== requirements.payTo.toLowerCase()) {
      return { isValid: false, invalidReason: "invalid_exact_evm_payload_recipient_mismatch" };
    }
    if (authorization.value !== requirements.amount) {
      return { isValid: false, invalidReason: "invalid_exact_evm_payload_value_mismatch" };
    }
    return { isValid: true };
  }

  settle(payload: PaymentPayload, requirements: PaymentRequirements): SettleOutcome {
    this.settleCalls.push({ payload, requirements });
    return this.behaviour.settle?.(payload, requirements) ?? { success: true, transaction: "0xtx" };
  }
}

export class SettlementFailure extends Error {
  override readonly name = "SettlementFailure";

  constructor(readonly reason: string) {
    super(`Settlement failed: ${reason}`);
  }
}

export type ResourceAccessResult =
  | { status: 200; body: string; transaction: string }
  | { status: 402; reason: string; reasonCodes?: string[] };

/**
 * A minimal x402-protected resource server wired in the order the Inntris
 * documentation prescribes: authorise under policy, ask the facilitator to
 * verify the payment, then settle behind the guard and only then release the
 * resource. Attacks are run against this loop rather than against the guard in
 * isolation, so a defence that exists only on paper cannot pass.
 */
export class GuardedResourceServer {
  served = 0;

  constructor(
    private readonly context: SecurityContext,
    readonly facilitator: FakeFacilitator,
  ) {}

  async access(input: {
    authorisationInput: X402SettlementInput;
    settlementInput?: X402SettlementInput;
    payload: PaymentPayload;
    executionRef: string;
    decision?: InntrisDecisionV1;
  }): Promise<ResourceAccessResult> {
    const settlementInput = input.settlementInput ?? input.authorisationInput;

    let decision = input.decision;
    if (decision === undefined) {
      try {
        decision = await this.context.guard.authorise(input.authorisationInput);
      } catch (error) {
        return {
          status: 402,
          reason: "authorisation_failed",
          ...(error instanceof InntrisGuardError ? { reasonCodes: error.reasonCodes } : {}),
        };
      }
    }
    if (decision.verdict !== "ALLOW") {
      return { status: 402, reason: "policy_verdict", reasonCodes: decision.reason_codes };
    }

    const verification = this.facilitator.verify(
      input.payload,
      settlementInput.paymentRequirements,
    );
    if (!verification.isValid) {
      return { status: 402, reason: verification.invalidReason };
    }

    let transaction: string;
    try {
      transaction = await this.context.guard.settleIfAuthorised(
        settlementInput,
        decision,
        input.executionRef,
        async () => {
          const outcome = this.facilitator.settle(
            input.payload,
            settlementInput.paymentRequirements,
          );
          if (!outcome.success) {
            throw new SettlementFailure(outcome.errorReason);
          }
          return outcome.transaction;
        },
      );
    } catch (error) {
      return {
        status: 402,
        reason: "settlement_blocked",
        ...(error instanceof InntrisGuardError ? { reasonCodes: error.reasonCodes } : {}),
      };
    }

    this.served += 1;
    return { status: 200, body: "research-report", transaction };
  }
}

export type EvidenceStatus = "PASS" | "FAIL";

export interface EvidenceEntry {
  id: string;
  attack: string;
  status: EvidenceStatus;
  expectation: string;
  observed: string;
  reason_codes: string[];
  settlement_invoked: boolean;
  resource_served: boolean;
}

const evidence: EvidenceEntry[] = [];

export function recordEvidence(entry: EvidenceEntry): void {
  evidence.push(entry);
}

export async function writeEvidence(path: string): Promise<void> {
  const report = {
    version: "inntris-x402-security-review-v1",
    suite: "USENIX x402 attack matrix",
    total: evidence.length,
    passed: evidence.filter((entry) => entry.status === "PASS").length,
    failed: evidence.filter((entry) => entry.status === "FAIL").length,
    results: evidence,
  };
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(report, null, 2)}\n`, "utf8");
}
