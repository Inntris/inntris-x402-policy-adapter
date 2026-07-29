#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

import {
  InntrisActionV1Schema,
  InntrisDecisionV1Schema,
  hashAction,
  hashPolicyObject,
} from "@inntris/decision-core";
import { parsePolicyText } from "@inntris/policy-engine";
import { Command } from "commander";

import { fetchExplicitKeyRegistry, readJsonFile, readLocalKeyRegistry } from "./io.js";
import { humanVerificationOutput, verifyDecision } from "./verify.js";

interface DecisionOptions {
  action: string;
  keys?: string;
  keysUrl?: string;
  expectedPolicyVersion?: string;
  at?: string;
  paymentRequirementsHash?: string;
  json?: boolean;
}

function parseAt(value: string | undefined): Date {
  const at = value === undefined ? new Date() : new Date(value);
  if (Number.isNaN(at.getTime())) {
    throw new Error("--at must be an ISO 8601 timestamp");
  }
  return at;
}

export async function runCli(argv = process.argv): Promise<number> {
  const program = new Command()
    .name("inntris-verify")
    .description("Verify Inntris decisions without an Inntris account or database")
    .showHelpAfterError();

  program
    .command("decision")
    .argument("<decision>", "Signed decision JSON file")
    .requiredOption("--action <path>", "Canonical action JSON file")
    .option("--keys <path>", "Local key-registry JSON file")
    .option("--keys-url <url>", "Explicit HTTPS key-registry URL")
    .option("--expected-policy-version <version>")
    .option("--at <timestamp>", "Execution time used for expiry validation")
    .option("--payment-requirements-hash <hash>")
    .option("--json", "Machine-readable JSON output")
    .action(async (decisionPath: string, options: DecisionOptions) => {
      if ((options.keys === undefined) === (options.keysUrl === undefined)) {
        throw new Error("Supply exactly one of --keys or --keys-url");
      }
      const registry =
        options.keys === undefined
          ? await fetchExplicitKeyRegistry(
              options.keysUrl ??
                (() => {
                  throw new Error("--keys-url is required when --keys is absent");
                })(),
            )
          : await readLocalKeyRegistry(options.keys);
      const result = verifyDecision({
        decision: await readJsonFile(decisionPath),
        action: await readJsonFile(options.action),
        keyRegistry: registry,
        at: parseAt(options.at),
        expectedPolicyVersion: options.expectedPolicyVersion,
        expectedPaymentRequirementsHash: options.paymentRequirementsHash,
      });
      process.stdout.write(
        options.json
          ? `${JSON.stringify(result, null, 2)}\n`
          : `${humanVerificationOutput(result)}\n`,
      );
      if (!result.valid) {
        process.exitCode = 1;
      }
    });

  program
    .command("hash-action")
    .argument("<action>")
    .action(async (actionPath: string) => {
      const action = InntrisActionV1Schema.parse(await readJsonFile(actionPath));
      process.stdout.write(`${hashAction(action)}\n`);
    });

  program
    .command("hash-policy")
    .argument("<policy>")
    .action(async (policyPath: string) => {
      const policy = parsePolicyText(await readFile(policyPath, "utf8"));
      process.stdout.write(`${hashPolicyObject(policy)}\n`);
    });

  program
    .command("inspect")
    .argument("<decision>")
    .option("--json")
    .action(async (decisionPath: string, options: { json?: boolean }) => {
      const decision = InntrisDecisionV1Schema.parse(await readJsonFile(decisionPath));
      const summary = {
        version: decision.version,
        decision_id: decision.decision_id,
        verdict: decision.verdict,
        action_hash: decision.action_hash,
        policy: decision.policy,
        issued_at: decision.issued_at,
        expires_at: decision.expires_at,
        key_id: decision.signing.key_id,
      };
      process.stdout.write(
        options.json
          ? `${JSON.stringify(summary, null, 2)}\n`
          : Object.entries(summary)
              .map(([key, value]) => `${key}: ${JSON.stringify(value)}`)
              .join("\n") + "\n",
      );
    });

  try {
    await program.parseAsync(argv);
    return process.exitCode === undefined ? 0 : Number(process.exitCode);
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    return 1;
  }
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await runCli();
}
