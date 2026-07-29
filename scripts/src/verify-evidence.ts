import { resolve } from "node:path";

import { readJsonFile, humanVerificationOutput, verifyDecision } from "@inntris/decision-verifier";

const root = resolve(".");
const decision = await readJsonFile(resolve(root, "evidence/allow.json"));
const action = await readJsonFile(resolve(root, "evidence/action.json"));
const keyRegistry = await readJsonFile(resolve(root, "fixtures/keys/registry.json"));
const result = verifyDecision({
  decision,
  action,
  keyRegistry,
  at: new Date("2026-07-29T09:30:30.000Z"),
  expectedPolicyVersion: "1",
});
process.stdout.write(`${humanVerificationOutput(result)}\n`);
if (!result.valid || result.verdict !== "ALLOW") {
  process.exitCode = 1;
}
