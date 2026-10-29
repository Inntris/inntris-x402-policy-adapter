import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type { InntrisActionV1 } from "@inntris/decision-core";
import { MtpExecutionClient } from "../../../packages/mtp-authority/test/fixtures/execution-client.snapshot.js";

export const input = JSON.parse(
  readFileSync(new URL("./input-v1.json", import.meta.url), "utf8"),
) as {
  identities: { org: string; agent: string; key: string; grant: string };
  action: InntrisActionV1;
};

export function coreWire() {
  const path =
    process.env.SAFR_CORE_WIRE_FIXTURE ??
    fileURLToPath(new URL("./authority-http-v1.json", import.meta.url));
  return JSON.parse(readFileSync(path, "utf8")) as {
    contract_version: string;
    responses: Record<string, Record<string, unknown>>;
  };
}

export function harness(response: Record<string, unknown>) {
  const calls: string[] = [];
  const client = new MtpExecutionClient({
    apiUrl: "https://core.example.test/",
    apiKey: "pr00-synthetic-credential",
    apiKeyId: input.identities.key,
    organisationId: input.identities.org,
    agentId: input.identities.agent,
    fetchImplementation: async (url) => {
      const destination = url instanceof Request ? url.url : url instanceof URL ? url.href : url;
      calls.push(destination);
      if (destination !== "https://core.example.test/authority/evaluate")
        throw new Error("Unexpected request: no consume or rail call is allowed in this fixture");
      return Response.json(response);
    },
  });
  return { client, calls };
}
