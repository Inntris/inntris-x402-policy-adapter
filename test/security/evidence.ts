import { mkdir, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { dirname, join, resolve } from "node:path";

/**
 * Where the first rejection of a request occurred. The layer is derived from
 * the observed call sequence, never assumed: a rejection is only attributed to
 * Inntris after verification if a facilitator call was actually observed
 * before it.
 */
export type RejectionLayer =
  | "INNTRIS_PREFLIGHT"
  | "INNTRIS_POST_VERIFY"
  | "FACILITATOR_VERIFY"
  | "FACILITATOR_SETTLE"
  | "CHAIN"
  | "NONE";

export type CaseStatus = "PASS" | "BORROWED" | "KNOWN_GAP" | "NOT_TESTED";

/** One observed run of an attack against one facilitator stand-in. */
export interface RunOutcome {
  rejected: boolean;
  layer: RejectionLayer;
  component: string;
  detail: string;
  reason_codes: string[];
  verify_calls: number;
  settlement_invoked: boolean;
  resource_served: boolean;
}

/**
 * A run that could not be performed because the attack premise requires
 * facilitator behaviour the stand-in cannot produce. Recorded explicitly so it
 * is never confused with a passing or a borrowed result.
 */
export interface NotExpressible {
  not_expressible: string;
}

export interface EvidenceEntry {
  id: string;
  deliverable: string;
  attack: string;
  status: CaseStatus;
  expectation: string;
  observed: string;
  /** Result against the rule-following facilitator stand-in. */
  compliant?: RunOutcome;
  /** Result against the stand-in that approves everything. */
  permissive?: RunOutcome | NotExpressible;
  /**
   * Which component owns the rule, once both runs are known.
   * `INNTRIS_CONTAINMENT` marks a case where the facilitator produced the
   * failure and the measured property is how Inntris contained it — distinct
   * from Inntris detecting the violation itself.
   */
  enforcement?: "INNTRIS" | "INNTRIS_CONTAINMENT" | "FACILITATOR" | "NONE" | "NOT_APPLICABLE";
  reason_codes: string[];
  settlement_invoked: boolean;
  resource_served: boolean;
  notes?: string;
}

const SHARD_DIR = resolve("evidence/security/shards");

const pending: EvidenceEntry[] = [];

export function recordEvidence(entry: EvidenceEntry): void {
  pending.push(entry);
}

/**
 * Writes this test file's contribution. Each file owns one shard so the suite
 * can grow without files racing for a single output.
 */
export async function flushEvidence(shard: string): Promise<void> {
  await mkdir(SHARD_DIR, { recursive: true });
  await writeFile(
    join(SHARD_DIR, `${shard}.json`),
    `${JSON.stringify(pending.splice(0, pending.length), null, 2)}\n`,
    "utf8",
  );
}

export async function clearShards(): Promise<void> {
  await rm(SHARD_DIR, { recursive: true, force: true });
}

export interface EvidenceBundle {
  version: "inntris-x402-security-review-v2";
  suite: string;
  baseline_commit: string;
  generated_from_seed: number;
  counts: Record<CaseStatus, number>;
  enforcement_counts: Record<string, number>;
  total: number;
  results: EvidenceEntry[];
}

/**
 * Merges every shard into the single reviewable bundle and returns its
 * SHA-256, which the review document quotes so post-fix runs can be compared
 * against this baseline.
 */
export async function mergeShards(input: {
  outputPath: string;
  baselineCommit: string;
  seed: number;
}): Promise<{ digest: string; bundle: EvidenceBundle }> {
  let files: string[];
  try {
    files = (await readdir(SHARD_DIR)).filter((name) => name.endsWith(".json")).sort();
  } catch {
    files = [];
  }

  const results: EvidenceEntry[] = [];
  for (const file of files) {
    const parsed = JSON.parse(await readFile(join(SHARD_DIR, file), "utf8")) as EvidenceEntry[];
    results.push(...parsed);
  }
  results.sort((left, right) => left.id.localeCompare(right.id));

  const counts: Record<CaseStatus, number> = {
    PASS: 0,
    BORROWED: 0,
    KNOWN_GAP: 0,
    NOT_TESTED: 0,
  };
  const enforcementCounts: Record<string, number> = {};
  for (const entry of results) {
    counts[entry.status] += 1;
    const owner = entry.enforcement ?? "UNRECORDED";
    enforcementCounts[owner] = (enforcementCounts[owner] ?? 0) + 1;
  }

  const bundle: EvidenceBundle = {
    version: "inntris-x402-security-review-v2",
    suite: "USENIX x402 baseline, round 3",
    baseline_commit: input.baselineCommit,
    generated_from_seed: input.seed,
    counts,
    enforcement_counts: enforcementCounts,
    total: results.length,
    results,
  };

  const serialised = `${JSON.stringify(bundle, null, 2)}\n`;
  await mkdir(dirname(input.outputPath), { recursive: true });
  await writeFile(input.outputPath, serialised, "utf8");
  const digest = createHash("sha256").update(serialised, "utf8").digest("hex");
  await writeFile(`${input.outputPath}.sha256`, `${digest}\n`, "utf8");
  return { digest, bundle };
}
