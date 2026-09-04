import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { z } from "zod";

import { AP2_COMMIT, AP2_REPOSITORY } from "./constants.js";
import type { StructuredAp2Verification, StructuredAp2Verifier } from "./types.js";

const ClaimsResultSchema = z
  .object({
    verified: z.boolean(),
    claims: z.record(z.string(), z.unknown()).optional(),
  })
  .strict();

const StructuredResultSchema = z
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
    closedMandate: ClaimsResultSchema.extend({ issuerJwt: z.string().optional() }).strict(),
    keyBinding: z.object({ verified: z.boolean() }).strict(),
    receipt: ClaimsResultSchema,
  })
  .strict();

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
          const parsed = StructuredResultSchema.parse(
            JSON.parse(Buffer.concat(stdout).toString("utf8")) as unknown,
          ) as StructuredAp2Verification;
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
