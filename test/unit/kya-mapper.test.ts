import { StrictKyaFinancialActionMapper } from "@inntris/kya-os-authority";
import { describe, expect, it } from "vitest";

const valid = {
  method: "tools/call",
  params: {
    name: "payments.transfer",
    arguments: {
      to: "did:web:merchant.example",
      amount: "42.00",
      currency: "USD",
      resource: "did:web:api.example:payments",
    },
  },
};

describe("strict KYA financial mapper", () => {
  it("maps only the exact payments.transfer request", () => {
    expect(new StrictKyaFinancialActionMapper().map(valid)).toEqual({
      action: "payments.transfer",
      amount: "42.00",
      currency: "USD",
      payee: "did:web:merchant.example",
      resource: "did:web:api.example:payments",
    });
  });

  it.each([
    [{ ...valid, method: "payments.transfer" }],
    [{ ...valid, params: { ...valid.params, name: "wallet.sweep" } }],
    [
      {
        ...valid,
        params: {
          ...valid.params,
          arguments: { ...valid.params.arguments, amount: "42.0000000" },
        },
      },
    ],
    [
      {
        ...valid,
        params: { ...valid.params, arguments: { ...valid.params.arguments, memo: "ignored" } },
      },
    ],
  ])("rejects non exact or non canonical requests", (request) => {
    expect(() => new StrictKyaFinancialActionMapper().map(request)).toThrow();
  });
});
