import { readFile } from "node:fs/promises";

import { KeyRegistrySchema, type KeyRegistry } from "@inntris/decision-core";

export async function readJsonFile(path: string): Promise<unknown> {
  return JSON.parse(await readFile(path, "utf8")) as unknown;
}

export async function readLocalKeyRegistry(path: string): Promise<KeyRegistry> {
  return KeyRegistrySchema.parse(await readJsonFile(path));
}

export async function fetchExplicitKeyRegistry(url: string): Promise<KeyRegistry> {
  const parsed = new URL(url);
  if (parsed.protocol !== "https:") {
    throw new Error("Remote key registry URLs must use HTTPS");
  }
  const response = await fetch(parsed, {
    redirect: "error",
    signal: AbortSignal.timeout(5_000),
    headers: { accept: "application/json" },
  });
  if (!response.ok) {
    throw new Error(`Key registry request failed with HTTP ${response.status}`);
  }
  return KeyRegistrySchema.parse(await response.json());
}
