import { expect, it } from "vitest";
import { coreWire, harness, input } from "./harness.js";

// Intentionally NOT xfail, skip or continue-on-error. PR00 records this blocker.
it("accepts the actual Core authority v1 approval without translating its semantics", async () => {
  const { client } = harness(coreWire().responses.allow!);
  await expect(client.evaluate(input.action, "pr00-issuance")).resolves.toMatchObject({
    grantId: input.identities.grant,
  });
});
