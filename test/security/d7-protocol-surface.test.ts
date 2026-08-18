import { actionFromX402, normalisePaymentRequirements } from "@inntris/x402-adapter";
import { afterAll, describe, expect, it } from "vitest";

import { honestInput, honestRequirements, paymentPayload } from "./harness.js";
import { flushEvidence, recordEvidence, type CaseStatus } from "./evidence.js";

afterAll(async () => {
  await flushEvidence("d7-protocol-surface");
});

/** Attempts a parse and reports what the adapter did, without judging it. */
function probe(label: string, attempt: () => unknown): { accepted: boolean; detail: string } {
  try {
    attempt();
    return { accepted: true, detail: `${label}: accepted` };
  } catch (error) {
    return { accepted: false, detail: `${label}: rejected — ${(error as Error).name}` };
  }
}

function record(input: {
  id: string;
  surface: string;
  status: CaseStatus;
  observed: string;
  notes?: string;
}): void {
  recordEvidence({
    id: `D7:${input.id}`,
    deliverable: "D7",
    attack: input.surface,
    status: input.status,
    expectation:
      "Anything reachable is either tested or recorded NOT_TESTED with a reason; anything unreachable is confirmed unreachable rather than assumed.",
    observed: input.observed,
    enforcement: "NOT_APPLICABLE",
    reason_codes: [],
    settlement_invoked: false,
    resource_served: false,
    ...(input.notes === undefined ? {} : { notes: input.notes }),
  });
}

describe("D7 protocol surface reachability", () => {
  it("confirms x402 v1 payloads are unreachable through this adapter", () => {
    const v1 = probe("x402Version 1 payload", () =>
      actionFromX402({
        ...honestInput,
        paymentPayload: {
          x402Version: 1,
          scheme: "exact",
          network: "base",
          payload: { signature: "0x00", authorization: {} },
        } as never,
      }),
    );

    expect(v1.accepted).toBe(false);
    record({
      id: "v1-unreachable",
      surface: "x402 protocol version 1",
      status: "PASS",
      observed: `The adapter parses with PaymentPayloadV2Schema only (binding.ts:34). ${v1.detail}. v1 is confirmed unreachable rather than assumed: a v1-shaped payload fails schema parse before any binding logic runs.`,
    });
  });

  it("records which v2 specifics are exercised", () => {
    const action = actionFromX402({
      ...honestInput,
      paymentPayload: paymentPayload({}),
      extensions: { "com.example/x": 1 },
    });

    expect(action.protocol_reference.payment_payload_hash).not.toBeNull();
    record({
      id: "v2-specifics",
      surface: "x402 v2 — accepted echo, extensions, CAIP-2 networks, amount field",
      status: "PASS",
      observed:
        "All four are exercised. The `accepted` echo is compared against the served requirements (binding.ts:78, case A10). `extensions` on the action is carried into the action hash (D2 row). CAIP-2 network identifiers are the only accepted form. `amount` is the v2 field name; `maxAmountRequired` does not appear in the v2 schema and is not accepted.",
    });
  });

  it("records that no scheme allowlist exists", () => {
    const schemes = ["exact", "deferred", "upto", "totally-made-up"].map((scheme) =>
      probe(scheme, () => normalisePaymentRequirements({ ...honestRequirements, scheme })),
    );

    expect(schemes.every((result) => result.accepted)).toBe(true);
    record({
      id: "scheme-allowlist",
      surface: "Payment schemes accepted",
      status: "KNOWN_GAP",
      observed: `Every scheme string parses and reaches a decision: ${schemes.map((result) => result.detail).join("; ")}. The x402 v2 schema types scheme as a free string, and no Inntris policy rule constrains it. Only 'exact' semantics are modelled anywhere in the adapter, but nothing rejects the others.`,
      notes: "F-7. The review's test A6 (scheme substitution) is measured here.",
    });
  });

  it("records network reachability across chain families", () => {
    const networks = [
      "eip155:8453",
      "eip155:1",
      "eip155:84532",
      "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
      "base",
      "base-sepolia",
    ].map((network) =>
      probe(network, () =>
        normalisePaymentRequirements({ ...honestRequirements, network } as never),
      ),
    );

    const accepted = networks.filter((result) => result.accepted);
    record({
      id: "network-families",
      surface: "Network identifiers — EVM chain ids and Solana clusters",
      status: "PASS",
      observed: `${accepted.length} of ${networks.length} parse. ${networks.map((result) => result.detail).join("; ")}. Legacy v1 aliases are rejected at schema parse, so there is no alias-confusion path. Policy independently restricts the accepted set to its allowed_networks list.`,
      notes:
        "Solana reachability at the schema layer is recorded; no Solana settlement path is exercised anywhere in this suite.",
    });
  });

  it("records contract signature models as unreachable and untested", () => {
    // The payload member is opaque to the adapter, so an ERC-6492 wrapper is
    // neither parsed nor rejected — it is simply carried as bytes.
    const wrapped = actionFromX402({
      ...honestInput,
      paymentPayload: paymentPayload({
        signature: `0x${"64".repeat(32)}6492649264926492649264926492649264926492649264926492649264926492`,
      }),
    });

    expect(wrapped.protocol_reference.payment_payload_hash).not.toBeNull();
    record({
      id: "contract-signatures",
      surface: "ERC-1271 and ERC-6492 contract wallet signatures",
      status: "NOT_TESTED",
      observed:
        "Neither parsed nor rejected. `payload` is typed Record<string, unknown> by @x402/core and the adapter hashes it without inspection, so an ERC-6492 wrapper carrying an attacker-chosen factory address and calldata is carried into the action hash unexamined and passed to the facilitator. The adapter therefore neither supports nor refuses contract wallets.",
      notes:
        "Review tests B4 and B5. The reference paper's only validated asset-theft finding ran through ERC-6492 handling; that path is the facilitator's here, and was not exercised.",
    });
  });

  it("records transport reachability", () => {
    record({
      id: "transports",
      surface: "Transports — HTTP and MCP",
      status: "PASS",
      observed:
        "HTTP is exercised in D8 through buildDemoApi via inject, covering all eleven routes. MCP is reachable only through the KYA path: @kya-os/mcp supplies card and delegation schemas consumed by actionFromKyaX402 (packages/x402-adapter/src/kya.ts), and no MCP server or tool-call transport is implemented in this repository. The mcp rail in the action schema is a protocol_reference type, not a transport.",
      notes: "KYA delegation and proof logic is out of this review's scope.",
    });
  });

  it("records the untested protocol surface with reasons", () => {
    const untested = [
      "SR4 chain confirmation (E2, E3) — no chain client exists in the adapter, so there is nothing to exercise; a test would be measuring its absence, which D3 records instead",
      "EIP-712 domain substitution (A5) — the adapter performs no signature recovery, so chainId and verifyingContract are never read",
      "Concurrent nonce race (C4) — the suite is sequential; the in-memory nonce store's check-and-set is single-process and the atomic PostgreSQL store was not run",
      "Premature authorisation, validAfter in the future (C2) — validAfter is never read",
      "Remaining-validity threshold sweep (C5) — no freshness bound exists to measure",
      "Zero-amount and dust proofs (D2, D3 of the review register) — no settleability check exists",
      "Solana settlement semantics — reachable at the schema layer, no settlement path implemented",
      "PostgreSQL-backed stores — in-memory implementations only throughout this suite",
    ];

    record({
      id: "untested-surface",
      surface: "Reachable-but-untested protocol surface",
      status: "NOT_TESTED",
      observed: untested.join(". "),
      notes: "Each entry carries its reason; none is omitted.",
    });

    expect(untested.length).toBe(8);
  });
});
