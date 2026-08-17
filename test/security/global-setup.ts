import { execFileSync } from "node:child_process";
import { resolve } from "node:path";

import { clearShards, mergeShards } from "./evidence.js";

/**
 * Fixed so the generated mutation corpus is identical between runs. Change it
 * only alongside a new baseline.
 */
export const CORPUS_SEED = 20260817;

/**
 * Clears the per-file evidence shards before the suite runs, then merges them
 * into the single reviewable bundle and prints its digest afterwards.
 */
export default async function setup(): Promise<() => Promise<void>> {
  await clearShards();

  return async () => {
    let commit: string;
    try {
      commit = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();
    } catch {
      commit = "unknown";
    }
    const { digest, bundle } = await mergeShards({
      outputPath: resolve("evidence/x402-security-review.json"),
      baselineCommit: commit,
      seed: CORPUS_SEED,
    });
    const counts = Object.entries(bundle.counts)
      .map(([status, count]) => `${status}=${count}`)
      .join(" ");
    process.stdout.write(
      `\nevidence bundle: ${bundle.total} cases (${counts})\nbaseline commit: ${commit}\nsha256: ${digest}\n`,
    );
  };
}
