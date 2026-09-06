import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { privateKeyToAccount } from "viem/accounts";
import {
  AP2StructuredPythonVerifier,
  EIP3009_AUTHORIZATION_TYPES,
  calculateInputHash,
  canonicalHash,
  type ConformanceCase,
} from "../../packages/pulse-conformance-evaluator/src/index.js";
import { makeConformanceCase } from "./helpers.js";

export const python =
  process.env.PULSE_AP2_PYTHON ??
  (existsSync(".venv/Scripts/python.exe") ? resolve(".venv/Scripts/python.exe") : "python");
export const realVerifier = new AP2StructuredPythonVerifier({ pythonExecutable: python });

export interface SigningOptions {
  root?: Record<string, unknown>;
  leaf?: Record<string, unknown>;
  receipt?: Record<string, unknown>;
  omitLeaf?: string[];
  rootDisclosure?: string;
  leafDisclosure?: string;
  corruptLeaf?: boolean;
}

export async function signCase(
  options: SigningOptions = {},
  customise?: (input: ConformanceCase) => void,
): Promise<ConformanceCase> {
  const seed = await makeConformanceCase();
  customise?.(seed);
  const process = spawnSync(python, ["-B", "test/pulse/signed-case.py"], {
    input: JSON.stringify({ case: seed, options }),
    encoding: "utf8",
    windowsHide: true,
  });
  if (process.status !== 0) throw new Error(process.stderr || "Regression signer failed");
  const input = JSON.parse(process.stdout) as ConformanceCase;
  const { authorization } = input.x402.payload.payload;
  const account = privateKeyToAccount(`0x${"0".repeat(63)}1`);
  input.x402.payload.payload.signature = await account.signTypedData({
    domain: {
      name: input.x402.requirements.extra.name,
      version: input.x402.requirements.extra.version,
      chainId: 31337n,
      verifyingContract: input.x402.requirements.asset,
    },
    types: EIP3009_AUTHORIZATION_TYPES,
    primaryType: "TransferWithAuthorization",
    message: {
      ...authorization,
      value: BigInt(authorization.value),
      validAfter: BigInt(authorization.validAfter),
      validBefore: BigInt(authorization.validBefore),
    },
  });
  input.ap2.verification.openMandateClaimsHash = canonicalHash(input.ap2.openMandate);
  input.ap2.verification.closedMandateClaimsHash = canonicalHash(input.ap2.closedMandate);
  input.inputHash = calculateInputHash(input);
  return input;
}
