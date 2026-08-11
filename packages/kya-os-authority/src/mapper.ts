import { KyaAuthorityError } from "./errors.js";
import { KyaPaymentRequestV1Schema, type KyaToolRequest } from "./schemas.js";
import type { KyaFinancialAction, KyaFinancialActionMapper } from "./types.js";

export class StrictKyaFinancialActionMapper implements KyaFinancialActionMapper {
  map(request: KyaToolRequest): KyaFinancialAction {
    const parsed = KyaPaymentRequestV1Schema.safeParse(request);
    if (!parsed.success) {
      throw new KyaAuthorityError(
        "KYA_PRESENTATION_INVALID",
        "financial_join",
        "KYA request is not the strict payments.transfer profile",
        { cause: parsed.error },
      );
    }
    return {
      action: "payments.transfer",
      amount: parsed.data.params.arguments.amount,
      currency: parsed.data.params.arguments.currency,
      payee: parsed.data.params.arguments.to,
      resource: parsed.data.params.arguments.resource,
    };
  }
}
