#!/usr/bin/env node

import { writeFile } from "node:fs/promises";

import { AP2StructuredPythonVerifier } from "./ap2-bridge.js";
import { evaluateBundle } from "./evaluator.js";
import { blindPinnedFixture, readBlindedBundle } from "./input.js";
import { createReproductionRecord } from "./record.js";

function parseFlags(args: string[]): Map<string, string> {
  const flags = new Map<string, string>();
  for (let index = 0; index < args.length; index += 1) {
    const key = args[index];
    if (key === "--") continue;
    const value = args[index + 1];
    if (
      key === undefined ||
      !key.startsWith("--") ||
      value === undefined ||
      value.startsWith("--")
    ) {
      throw new TypeError(`Invalid command argument: ${key ?? "<missing>"}`);
    }
    if (flags.has(key)) throw new TypeError(`Duplicate command argument: ${key}`);
    flags.set(key, value);
    index += 1;
  }
  return flags;
}

function takeRequired(flags: Map<string, string>, key: string): string {
  const value = flags.get(key);
  if (value === undefined || value === "") throw new TypeError(`${key} is required`);
  flags.delete(key);
  return value;
}

function takeOptional(flags: Map<string, string>, key: string): string | undefined {
  const value = flags.get(key);
  flags.delete(key);
  return value;
}

function rejectUnknown(flags: Map<string, string>): void {
  const first = flags.keys().next().value;
  if (first !== undefined) throw new TypeError(`Unknown command argument: ${first}`);
}

async function runBlind(args: string[]): Promise<void> {
  const flags = parseFlags(args);
  const source = takeRequired(flags, "--source");
  const output = takeRequired(flags, "--output");
  rejectUnknown(flags);
  await blindPinnedFixture(source, output);
  process.stdout.write(`Verified and blinded the pinned fixture to ${output}\n`);
}

async function runEvaluate(args: string[]): Promise<void> {
  const flags = parseFlags(args);
  const input = takeRequired(flags, "--input");
  const recordPath = takeRequired(flags, "--record");
  const implementationCommit = takeRequired(flags, "--implementation-commit");
  const organization = takeRequired(flags, "--organization");
  const publishedUrl = takeRequired(flags, "--published-url");
  const repositoryUrl = takeOptional(flags, "--repository-url");
  const performedAt = takeOptional(flags, "--performed-at");
  const notes = takeOptional(flags, "--notes");
  const command = takeOptional(flags, "--command");
  const pythonExecutable = takeOptional(flags, "--python");
  rejectUnknown(flags);

  const bundle = await readBlindedBundle(input);
  const results = await evaluateBundle(
    bundle,
    new AP2StructuredPythonVerifier(pythonExecutable === undefined ? {} : { pythonExecutable }),
  );
  const options = {
    implementationCommit,
    organization,
    publishedUrl,
    ...(repositoryUrl === undefined ? {} : { repositoryUrl }),
    ...(performedAt === undefined ? {} : { performedAt }),
    ...(notes === undefined ? {} : { notes }),
    ...(command === undefined ? {} : { command }),
  };
  const record = createReproductionRecord(results, options);
  await writeFile(recordPath, `${JSON.stringify(record, null, 2)}\n`, {
    encoding: "utf8",
    flag: "wx",
  });
  const accepted = results.filter((result) => result.decision === "accept").length;
  process.stdout.write(
    `Wrote ${results.length} independent results to ${recordPath}: ${accepted} accept, ${results.length - accepted} reject\n`,
  );
}

async function main(): Promise<void> {
  const [command, ...args] = process.argv.slice(2);
  if (command === "blind") await runBlind(args);
  else if (command === "evaluate") await runEvaluate(args);
  else throw new TypeError("Usage: inntris-pulse-conformance <blind|evaluate> [arguments]");
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "Unknown evaluator failure";
  process.stderr.write(`PULSE_CONFORMANCE_FAILED: ${message}\n`);
  process.exitCode = 1;
});
