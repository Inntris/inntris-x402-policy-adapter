/** Summarise our own Vitest runs, never corpus expected values. */
import { readFile, writeFile } from "node:fs/promises";

interface VitestReport {
  numTotalTests: number;
  numPassedTests: number;
  numFailedTests: number;
  testResults: { assertionResults: { fullName: string; status: string }[] }[];
}

const [redPath, greenPath, outputPath, implementationCommit] = process.argv.slice(2);
if (!redPath || !greenPath || !outputPath || !implementationCommit) {
  throw new Error(
    "Usage: report-regressions.ts <red.json> <green.json> <output.json> <implementation-commit>",
  );
}
const red = JSON.parse(await readFile(redPath, "utf8")) as VitestReport;
const green = JSON.parse(await readFile(greenPath, "utf8")) as VitestReport;
const previous = new Map(
  red.testResults
    .flatMap((file) => file.assertionResults)
    .map((result) => [result.fullName, result.status]),
);
const results = green.testResults
  .flatMap((file) => file.assertionResults)
  .map((result) => ({
    test: result.fullName,
    baseline: previous.get(result.fullName) ?? "supplementary observation or control",
    remediated: result.status,
  }));
if (
  results.length !== green.numTotalTests ||
  results.some((result) => result.remediated !== "passed")
) {
  throw new Error("Current regression run is incomplete or failing");
}
await writeFile(
  outputPath,
  JSON.stringify(
    {
      frozenImplementation: "5a2c65ea10dc3078d3b38971db7373f1f34cac7c",
      regressionCommit: "4353a5c",
      implementationCommit,
      baseline: {
        total: red.numTotalTests,
        passed: red.numPassedTests,
        failed: red.numFailedTests,
      },
      remediated: {
        total: green.numTotalTests,
        passed: green.numPassedTests,
        failed: green.numFailedTests,
      },
      note: "Specification-boundary observations document limits, not authorisation guarantees. No Pulse expected values or reference validator were used.",
      results,
    },
    null,
    2,
  ) + "\n",
  { flag: "wx" },
);
