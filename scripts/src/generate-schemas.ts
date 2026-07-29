import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

import {
  InntrisActionV1Schema,
  InntrisDecisionV1Schema,
  KeyRegistrySchema,
} from "@inntris/decision-core";
import { InntrisPolicyV1Schema } from "@inntris/policy-engine";
import { format } from "prettier";
import { toJSONSchema, type ZodType } from "zod";

const schemas: [string, string, ZodType][] = [
  ["inntris-action-v1.schema.json", "Inntris Action v1", InntrisActionV1Schema],
  ["inntris-decision-v1.schema.json", "Inntris Decision v1", InntrisDecisionV1Schema],
  ["inntris-key-registry-v1.schema.json", "Inntris Key Registry v1", KeyRegistrySchema],
  ["inntris-policy-v1.schema.json", "Inntris Policy v1", InntrisPolicyV1Schema],
];

const directory = resolve("schemas");
await mkdir(directory, { recursive: true });
for (const [filename, title, schema] of schemas) {
  const jsonSchema = {
    $id: `https://schemas.inntris.com/${filename}`,
    title,
    ...toJSONSchema(schema, {
      target: "draft-2020-12",
      unrepresentable: "any",
    }),
  };
  await writeFile(
    resolve(directory, filename),
    await format(JSON.stringify(jsonSchema), { parser: "json", printWidth: 100 }),
    "utf8",
  );
}
process.stdout.write(`Generated ${schemas.length} JSON schemas\n`);
