#!/usr/bin/env node

import {
  buildKeyRegistryEntry,
  createPublicDemoSigner,
  type Clock,
  type KeyRegistry,
} from "@inntris/decision-core";
import { LocalPolicyDecisionProvider, loadPolicyFile } from "@inntris/policy-engine";

import { createPublicConformanceCases } from "./fixtures.js";
import { runMultiRailConformance } from "./suite.js";

const clock: Clock = { now: () => new Date("2026-07-29T12:00:00.000Z") };

async function main(): Promise<void> {
  const policy = await loadPolicyFile("policies/multi-rail-conformance.yml");
  const signer = createPublicDemoSigner();
  const keyRegistry: KeyRegistry = {
    version: "inntris-key-registry-v1",
    keys: [
      buildKeyRegistryEntry(signer, {
        notBefore: new Date("2026-01-01T00:00:00.000Z"),
      }),
    ],
  };
  const provider = new LocalPolicyDecisionProvider({ policy, signer, clock });
  const report = await runMultiRailConformance({
    cases: createPublicConformanceCases(),
    provider,
    keyRegistry,
    expectedPolicyVersion: policy.policy_version,
    clock,
  });

  process.stdout.write("Inntris multi-rail conformance\n\n");
  process.stdout.write(`PASS one shared policy ${report.policy_hash}\n`);
  process.stdout.write("PASS one inntris-decision-v1 envelope and one offline verifier\n");
  for (const outcome of report.outcomes) {
    process.stdout.write(
      `PASS ${outcome.rail}: ALLOW verifies; exact action mutation is rejected\n`,
    );
  }
  process.stdout.write("\nCONFORMANCE: PASS\n");
}

main().catch((error: unknown) => {
  process.stderr.write(
    `CONFORMANCE: FAIL ${error instanceof Error ? error.message : "unknown error"}\n`,
  );
  process.exitCode = 1;
});
