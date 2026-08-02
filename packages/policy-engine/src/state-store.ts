import type { ConsumeDecisionResult, NonceConsumption } from "@inntris/decision-core";

import type { DecisionStateStore } from "./decision-store.js";
import type { RecordSpendInput, SpendState } from "./evaluate.js";

export interface AtomicConsumptionInput {
  consumption: NonceConsumption;
  spend: RecordSpendInput;
  dailyLimit: string;
}

/**
 * Durable policy state used at the financial execution boundary.
 *
 * `consumeAndRecordSpend` must commit the nonce consumption and cumulative
 * spend increment in one transaction. It must also recheck the daily limit
 * while holding the database write lock so concurrently issued decisions
 * cannot exceed that limit.
 */
export interface AtomicPolicyStateStore extends DecisionStateStore, SpendState {
  consumeAndRecordSpend(input: AtomicConsumptionInput): Promise<ConsumeDecisionResult>;
}
