import {
  type Approval,
  type Clock,
  type InntrisActionV1,
  type ReasonCode,
  type UnsignedEvaluation,
} from "@inntris/decision-core";
import { Decimal } from "decimal.js";

import type { InntrisPolicyV1, Weekday } from "./policy.js";

export interface RecordSpendInput {
  principalId: string;
  dayKey: string;
  amount: string;
}

export interface SpendState {
  getDailySpend(principalId: string, dayKey: string): Promise<string>;
  /**
   * Adds a settled amount to the cumulative daily total. The executor records
   * spend when a decision is consumed for the first time, because consumption
   * is the single-use gate that immediately precedes settlement.
   */
  recordSpend(input: RecordSpendInput): Promise<void>;
}

/**
 * A deliberately non-accumulating spend state. Cumulative limits are evaluated
 * against a permanent zero, so it is only suitable for demonstrations and for
 * deployments that enforce cumulative limits elsewhere.
 */
export class ZeroSpendState implements SpendState {
  async getDailySpend(): Promise<string> {
    return "0.00";
  }

  async recordSpend(): Promise<void> {
    return undefined;
  }
}

export function toCanonicalAmount(value: Decimal): string {
  const [whole, fraction = ""] = value.toFixed().split(".");
  return `${whole}.${fraction.padEnd(2, "0")}`;
}

export class InMemorySpendState implements SpendState {
  readonly #spend = new Map<string, string>();

  setDailySpend(principalId: string, dayKey: string, amount: string): void {
    this.#spend.set(`${principalId}:${dayKey}`, amount);
  }

  async getDailySpend(principalId: string, dayKey: string): Promise<string> {
    return this.#spend.get(`${principalId}:${dayKey}`) ?? "0.00";
  }

  async recordSpend(input: RecordSpendInput): Promise<void> {
    const key = `${input.principalId}:${input.dayKey}`;
    const current = new Decimal(this.#spend.get(key) ?? "0.00");
    this.#spend.set(key, toCanonicalAmount(current.plus(new Decimal(input.amount))));
  }
}

const weekdayMap: Record<string, Weekday> = {
  Mon: "MONDAY",
  Tue: "TUESDAY",
  Wed: "WEDNESDAY",
  Thu: "THURSDAY",
  Fri: "FRIDAY",
  Sat: "SATURDAY",
  Sun: "SUNDAY",
};

function block(reason: ReasonCode): UnsignedEvaluation {
  return {
    verdict: "BLOCK",
    reasonCodes: [reason],
    approval: {
      mode: "policy_engine",
      approval_reference: null,
      approver_ids: [],
    },
  };
}

function approval(mode: Approval["mode"]): Approval {
  return {
    mode,
    approval_reference: null,
    approver_ids: [],
  };
}

function localTimeParts(
  at: Date,
  timeZone: string,
): {
  weekday: Weekday;
  time: string;
  dayKey: string;
} {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone,
    weekday: "short",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hourCycle: "h23",
  }).formatToParts(at);
  const value = (type: Intl.DateTimeFormatPartTypes): string => {
    const part = parts.find((entry) => entry.type === type)?.value;
    if (part === undefined) {
      throw new Error(`Intl formatter did not return ${type}`);
    }
    return part;
  };
  const weekday = weekdayMap[value("weekday")];
  if (weekday === undefined) {
    throw new Error("Unsupported weekday emitted by Intl");
  }
  return {
    weekday,
    time: `${value("hour")}:${value("minute")}`,
    dayKey: `${value("year")}-${value("month")}-${value("day")}`,
  };
}

/**
 * The cumulative-limit day key for an instant in the policy timezone.
 */
export function spendDayKey(at: Date, timeZone: string): string {
  return localTimeParts(at, timeZone).dayKey;
}

/**
 * A window whose start is later than its end crosses local midnight. Both ends
 * are inclusive, and the weekday is always the weekday of the evaluated
 * instant, so the post-midnight part of a crossing window belongs to the
 * following day.
 */
export function withinTimeWindow(time: string, start: string, end: string): boolean {
  return start <= end ? time >= start && time <= end : time >= start || time <= end;
}

function deniedByExplicitRule(action: InntrisActionV1, policy: InntrisPolicyV1): ReasonCode | null {
  const deny = policy.deny;
  if (deny === undefined) {
    return null;
  }
  if (deny.networks.includes(action.transaction.network)) return "NETWORK_NOT_ALLOWED";
  if (deny.assets.includes(action.transaction.asset)) return "ASSET_NOT_ALLOWED";
  if (deny.payees.includes(action.transaction.payee)) return "PAYEE_NOT_ALLOWED";
  if (deny.resources.includes(action.protocol_reference.resource)) return "RESOURCE_NOT_ALLOWED";
  if (deny.purposes.includes(action.transaction.purpose)) return "PURPOSE_NOT_ALLOWED";
  return null;
}

export async function evaluatePolicy(input: {
  action: InntrisActionV1;
  policy: InntrisPolicyV1;
  spendState: SpendState;
  clock: Clock;
}): Promise<UnsignedEvaluation> {
  const { action, policy } = input;
  const now = input.clock.now();

  if (policy.expires_at !== undefined && now.getTime() >= Date.parse(policy.expires_at)) {
    return block("POLICY_EXPIRED");
  }

  const explicitDeny = deniedByExplicitRule(action, policy);
  if (explicitDeny !== null) {
    return block(explicitDeny);
  }

  const railPolicy = policy.rails[action.rail];
  if (railPolicy === undefined) {
    return block("DEFAULT_DENY");
  }
  if (!railPolicy.allowed_networks.includes(action.transaction.network)) {
    return block("NETWORK_NOT_ALLOWED");
  }
  if (!railPolicy.allowed_assets.includes(action.transaction.asset)) {
    return block("ASSET_NOT_ALLOWED");
  }

  const payeeMerchants = policy.merchants.filter((merchant) =>
    merchant.payees.includes(action.transaction.payee),
  );
  if (payeeMerchants.length === 0) {
    return block("PAYEE_NOT_ALLOWED");
  }
  const resourceMerchants = payeeMerchants.filter((merchant) =>
    merchant.resources.includes(action.protocol_reference.resource),
  );
  if (resourceMerchants.length === 0) {
    return block("RESOURCE_NOT_ALLOWED");
  }
  const matchingMerchant = resourceMerchants.find((merchant) =>
    merchant.purposes.includes(action.transaction.purpose),
  );
  if (matchingMerchant === undefined) {
    return block("PURPOSE_NOT_ALLOWED");
  }

  const amount = new Decimal(action.transaction.amount);
  const transactionLimit = Decimal.min(
    new Decimal(policy.limits.per_transaction),
    new Decimal(matchingMerchant.per_transaction_limit),
  );
  if (amount.greaterThan(transactionLimit)) {
    return block("AMOUNT_EXCEEDS_TRANSACTION_LIMIT");
  }

  const local = localTimeParts(now, policy.time_windows.timezone);
  const dailySpend = new Decimal(
    await input.spendState.getDailySpend(action.principal_id, local.dayKey),
  );
  if (dailySpend.plus(amount).greaterThan(new Decimal(policy.limits.daily))) {
    return block("DAILY_LIMIT_EXCEEDED");
  }

  if (
    !policy.time_windows.allowed_weekdays.includes(local.weekday) ||
    !withinTimeWindow(local.time, policy.time_windows.start, policy.time_windows.end)
  ) {
    return block("OUTSIDE_ALLOWED_TIME");
  }

  const positiveReasons: ReasonCode[] = [
    "MERCHANT_ALLOWED",
    "WITHIN_TRANSACTION_LIMIT",
    "WITHIN_DAILY_LIMIT",
  ];
  if (amount.greaterThan(new Decimal(policy.approval.require_human_above))) {
    return {
      verdict: "REQUIRE_APPROVAL",
      reasonCodes: [...positiveReasons, "HUMAN_APPROVAL_REQUIRED"],
      approval: approval("human"),
    };
  }

  return {
    verdict: "ALLOW",
    reasonCodes: positiveReasons,
    approval: approval("policy_engine"),
  };
}
