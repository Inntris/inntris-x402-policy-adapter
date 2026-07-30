import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

import {
  AP2OfficialVerificationRequestSchema,
  type AP2OfficialVerificationRequest,
  type AP2OfficialVerifier,
} from "./types.js";

export interface AP2PythonSdkVerifierOptions {
  pythonExecutable?: string;
  bridgePath?: string;
  timeoutMs?: number;
  maxOutputBytes?: number;
}

export class AP2PythonSdkVerifierError extends Error {
  override readonly name = "AP2PythonSdkVerifierError";
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
    if (value !== undefined && allowed.has(key.toUpperCase())) {
      environment[key] = value;
    }
  }
  return environment;
}

export class AP2PythonSdkVerifier implements AP2OfficialVerifier {
  readonly #bridgePath: string;
  readonly #maxOutputBytes: number;
  readonly #pythonExecutable: string;
  readonly #timeoutMs: number;

  constructor(options: AP2PythonSdkVerifierOptions = {}) {
    this.#pythonExecutable = options.pythonExecutable ?? "python";
    this.#bridgePath =
      options.bridgePath ?? fileURLToPath(new URL("../python/verify_ap2.py", import.meta.url));
    this.#timeoutMs = options.timeoutMs ?? 15_000;
    this.#maxOutputBytes = options.maxOutputBytes ?? 1_000_000;
    if (!Number.isInteger(this.#timeoutMs) || this.#timeoutMs < 1 || this.#timeoutMs > 60_000) {
      throw new TypeError("timeoutMs must be an integer from 1 to 60000");
    }
    if (
      !Number.isInteger(this.#maxOutputBytes) ||
      this.#maxOutputBytes < 1_024 ||
      this.#maxOutputBytes > 10_000_000
    ) {
      throw new TypeError("maxOutputBytes must be an integer from 1024 to 10000000");
    }
  }

  async verify(input: AP2OfficialVerificationRequest): Promise<unknown> {
    const request = AP2OfficialVerificationRequestSchema.parse(input);
    return new Promise((resolve, reject) => {
      const child = spawn(this.#pythonExecutable, [this.#bridgePath], {
        env: pythonEnvironment(),
        stdio: ["pipe", "pipe", "pipe"],
        windowsHide: true,
      });
      const stdout: Buffer[] = [];
      const stderr: Buffer[] = [];
      let stderrBytes = 0;
      let outputBytes = 0;
      let settled = false;
      const finish = (error?: Error, value?: unknown): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (error === undefined) resolve(value);
        else reject(error);
      };
      const timer = setTimeout(() => {
        child.kill();
        finish(new AP2PythonSdkVerifierError("Official AP2 SDK verification timed out"));
      }, this.#timeoutMs);

      child.stdout.on("data", (chunk: Buffer) => {
        outputBytes += chunk.byteLength;
        if (outputBytes > this.#maxOutputBytes) {
          child.kill();
          finish(new AP2PythonSdkVerifierError("Official AP2 SDK output exceeded the limit"));
          return;
        }
        stdout.push(chunk);
      });
      child.stderr.on("data", (chunk: Buffer) => {
        const remaining = 8_192 - stderrBytes;
        if (remaining <= 0) return;
        const bounded = chunk.subarray(0, remaining);
        stderr.push(bounded);
        stderrBytes += bounded.byteLength;
      });
      child.stdin.on("error", () => {
        finish(new AP2PythonSdkVerifierError("Official AP2 SDK process rejected its input"));
      });
      child.on("error", () => {
        finish(new AP2PythonSdkVerifierError("Official AP2 SDK process could not start"));
      });
      child.on("close", (code) => {
        if (settled) return;
        if (code !== 0) {
          finish(
            new AP2PythonSdkVerifierError(
              `Official AP2 SDK rejected the mandate set${
                stderr.length === 0 ? "" : `: ${Buffer.concat(stderr).toString("utf8").trim()}`
              }`,
            ),
          );
          return;
        }
        try {
          finish(undefined, JSON.parse(Buffer.concat(stdout).toString("utf8")) as unknown);
        } catch {
          finish(new AP2PythonSdkVerifierError("Official AP2 SDK returned invalid JSON"));
        }
      });
      child.stdin.end(JSON.stringify(request));
    });
  }
}
