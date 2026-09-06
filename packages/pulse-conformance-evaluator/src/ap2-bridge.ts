import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { z } from "zod";

import { AP2_COMMIT, AP2_REPOSITORY } from "./constants.js";
import type { StructuredAp2Verification, StructuredAp2Verifier } from "./types.js";
import { assertJsonValue, parseStrictJson } from "./strict-json.js";

const ClaimsResultSchema = z.discriminatedUnion("status", [
  z
    .object({
      status: z.literal("verified"),
      claims: z.record(z.string(), z.unknown()),
    })
    .strict(),
  z.object({ status: z.literal("invalid") }).strict(),
  z.object({ status: z.literal("notEvaluated") }).strict(),
]);

const ClosedMandateResultSchema = z.discriminatedUnion("status", [
  z
    .object({
      status: z.literal("verified"),
      claims: z.record(z.string(), z.unknown()),
      issuerJwt: z.string().min(1),
    })
    .strict(),
  z.object({ status: z.literal("invalid") }).strict(),
  z.object({ status: z.literal("notEvaluated") }).strict(),
]);

const StatusResultSchema = z
  .object({ status: z.enum(["verified", "invalid", "notEvaluated"]) })
  .strict();

const NumericDate = z.number().min(-Number.MAX_SAFE_INTEGER).max(Number.MAX_SAFE_INTEGER);
const TimeResultSchema = z
  .object({
    status: z.enum(["verified", "invalid", "notEvaluated"]),
    expiryBounds: z
      .array(
        z
          .object({
            source: z.enum(["rootJwt", "openMandate", "closedJwt", "closedMandate"]),
            expiresAt: NumericDate,
          })
          .strict(),
      )
      .max(4)
      .default([]),
    effectiveAuthorityExpiry: NumericDate.optional(),
  })
  .strict()
  .superRefine((time, ctx) => {
    const sources = new Set(time.expiryBounds.map((bound) => bound.source));
    const minimum =
      time.expiryBounds.length === 0
        ? undefined
        : Math.min(...time.expiryBounds.map((bound) => bound.expiresAt));
    if (
      sources.size !== time.expiryBounds.length ||
      minimum !== time.effectiveAuthorityExpiry ||
      (time.status === "verified" && (!sources.has("openMandate") || !sources.has("closedMandate")))
    ) {
      ctx.addIssue({ code: "custom", message: "Incomplete or inconsistent signed expiry bounds" });
    }
  });

export const StructuredResultSchema = z
  .object({
    version: z.literal("inntris-pulse-ap2-structured-verification/0.1"),
    sdk: z
      .object({
        repository: z.literal(AP2_REPOSITORY),
        commit: z.literal(AP2_COMMIT),
        protocolVersion: z.literal("0.2"),
      })
      .strict(),
    openMandate: ClaimsResultSchema,
    closedMandate: ClosedMandateResultSchema,
    keyBinding: StatusResultSchema,
    mandateTime: TimeResultSchema,
    receipt: ClaimsResultSchema,
  })
  .strict();

// Adding a mandatory stage to the contract requires updating this exhaustive map.
const MANDATORY_STAGES = {
  openMandate: true,
  closedMandate: true,
  keyBinding: true,
  mandateTime: true,
  receipt: true,
} satisfies Record<Exclude<keyof StructuredAp2Verification, "version" | "sdk">, true>;

export function allMandatoryStagesVerified(result: StructuredAp2Verification | undefined): boolean {
  return (
    result !== undefined &&
    (Object.keys(MANDATORY_STAGES) as (keyof typeof MANDATORY_STAGES)[]).every(
      (stage) => result[stage].status === "verified",
    )
  );
}

export function parseStructuredVerification(value: unknown): StructuredAp2Verification {
  assertJsonValue(value);
  return StructuredResultSchema.parse(value) as StructuredAp2Verification;
}

export interface AP2StructuredPythonVerifierOptions {
  pythonExecutable?: string;
  bridgePath?: string;
  timeoutMs?: number;
  maxOutputBytes?: number;
}

export class AP2StructuredPythonVerifierError extends Error {
  override readonly name = "AP2StructuredPythonVerifierError";
}

function pythonEnvironment(): NodeJS.ProcessEnv {
  const environment: NodeJS.ProcessEnv = {
    PYTHONDONTWRITEBYTECODE: "1",
    PYTHONNOUSERSITE: "1",
    PYTHONUTF8: "1",
  };
  const allowed = new Set([
    "PATH",
    "SYSTEMROOT",
    "WINDIR",
    "TEMP",
    "TMP",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "LD_LIBRARY_PATH",
  ]);
  for (const [key, value] of Object.entries(process.env)) {
    if (value !== undefined && allowed.has(key.toUpperCase())) environment[key] = value;
  }
  return environment;
}

export class AP2StructuredPythonVerifier implements StructuredAp2Verifier {
  readonly #bridgePath: string;
  readonly #maxOutputBytes: number;
  readonly #pythonExecutable: string;
  readonly #timeoutMs: number;

  constructor(options: AP2StructuredPythonVerifierOptions = {}) {
    this.#pythonExecutable = options.pythonExecutable ?? process.env.PULSE_AP2_PYTHON ?? "python";
    this.#bridgePath =
      options.bridgePath ??
      fileURLToPath(new URL("../python/verify_ap2_structured.py", import.meta.url));
    this.#timeoutMs = options.timeoutMs ?? 30_000;
    this.#maxOutputBytes = options.maxOutputBytes ?? 2_000_000;
  }

  async verify(
    input: Parameters<StructuredAp2Verifier["verify"]>[0],
  ): Promise<StructuredAp2Verification> {
    return await new Promise((resolve, reject) => {
      const child = spawn(this.#pythonExecutable, [this.#bridgePath], {
        env: pythonEnvironment(),
        stdio: ["pipe", "pipe", "pipe"],
        windowsHide: true,
      });
      const stdout: Buffer[] = [];
      const stderr: Buffer[] = [];
      let bytes = 0;
      let settled = false;
      const finish = (error?: Error, value?: StructuredAp2Verification): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (error !== undefined) reject(error);
        else if (value !== undefined) resolve(value);
      };
      const timer = setTimeout(() => {
        child.kill();
        finish(new AP2StructuredPythonVerifierError("Structured AP2 verification timed out"));
      }, this.#timeoutMs);
      child.stdout.on("data", (chunk: Buffer) => {
        bytes += chunk.byteLength;
        if (bytes > this.#maxOutputBytes) {
          child.kill();
          finish(new AP2StructuredPythonVerifierError("Structured AP2 output exceeded the limit"));
          return;
        }
        stdout.push(chunk);
      });
      child.stderr.on("data", (chunk: Buffer) => {
        if (Buffer.concat(stderr).byteLength < 8_192) stderr.push(chunk.subarray(0, 8_192));
      });
      child.on("error", () => {
        finish(new AP2StructuredPythonVerifierError("Structured AP2 verifier could not start"));
      });
      child.stdin.on("error", () => {
        finish(new AP2StructuredPythonVerifierError("Structured AP2 verifier rejected its input"));
      });
      child.on("close", (code) => {
        if (settled) return;
        if (code !== 0) {
          const detail = Buffer.concat(stderr).toString("utf8").trim();
          finish(
            new AP2StructuredPythonVerifierError(
              detail === ""
                ? "Structured AP2 verifier failed"
                : `Structured AP2 verifier failed: ${detail}`,
            ),
          );
          return;
        }
        try {
          const parsed = parseStructuredVerification(
            parseStrictJson(
              new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(stdout)),
            ),
          );
          finish(undefined, parsed);
        } catch {
          finish(
            new AP2StructuredPythonVerifierError("Structured AP2 verifier returned invalid JSON"),
          );
        }
      });
      child.stdin.end(
        JSON.stringify({
          version: "inntris-pulse-ap2-structured-request/0.1",
          ...input,
        }),
      );
    });
  }
}
