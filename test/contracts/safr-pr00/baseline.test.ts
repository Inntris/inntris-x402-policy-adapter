import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { expect, it } from "vitest";
import { coreWire, harness, input } from "./harness.js";

it("preserves the observed v1 fixture and reproduces rejection specifically at decision", async () => {
  const wire = coreWire();
  expect(wire.contract_version).toBe("inntris-core-authority-http-observed-v1");
  const response = wire.responses.allow!;
  expect(response.decision).toBe("allow");
  const { client, calls } = harness(response);
  expect(client.bind(input.action).executionActionHash).toBe(response.execution_action_hash);
  await expect(client.evaluate(input.action, "pr00-issuance")).rejects.toMatchObject({
    issues: [{ path: ["decision"], code: "invalid_value" }],
  });
  expect(calls).toEqual(["https://core.example.test/authority/evaluate"]);
});

it("isolates letter case with a synthetic uppercase control, not a production conversion", async () => {
  const response = { ...coreWire().responses.allow, decision: "ALLOW" };
  const { client } = harness(response);
  await expect(client.evaluate(input.action, "pr00-issuance")).resolves.toMatchObject({
    grantId: input.identities.grant,
  });
});

it.each(["block", "require_approval"])("preserves %s as non executable", async (name) => {
  const response = coreWire().responses[name]!;
  expect(response.authority_token).toBeNull();
  expect(response.grant_id).toBeNull();
  const { client, calls } = harness(response);
  await expect(client.evaluate(input.action, "pr00-issuance")).rejects.toThrow();
  expect(calls).toHaveLength(1);
});

it.each(["Allow", "ALLOW ", "observe", "", null])(
  "rejects unknown decision %s",
  async (decision) => {
    const { client } = harness({ ...coreWire().responses.allow, decision });
    await expect(client.evaluate(input.action, "pr00-issuance")).rejects.toThrow();
  },
);

it("pins the unfinished client snapshot instead of claiming it is released source", () => {
  const metadata = JSON.parse(
    readFileSync(new URL("./snapshot-provenance.json", import.meta.url), "utf8"),
  ) as { normalized_sha256: string; released: boolean };
  const source = readFileSync(
    new URL(
      "../../../packages/mtp-authority/test/fixtures/execution-client.snapshot.ts",
      import.meta.url,
    ),
    "utf8",
  );
  expect(metadata.released).toBe(false);
  expect(createHash("sha256").update(source.replaceAll("\r\n", "\n")).digest("hex")).toBe(
    metadata.normalized_sha256,
  );
});
