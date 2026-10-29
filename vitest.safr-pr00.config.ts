import { readdirSync } from "node:fs";
import { resolve } from "node:path";
import { defineConfig } from "vitest/config";

const root = import.meta.dirname;

export default defineConfig({
  resolve: {
    alias: {
      ...Object.fromEntries(
        readdirSync(resolve(root, "packages")).map((name) => [
          "@inntris/" + name,
          resolve(root, "packages", name, "src/index.ts"),
        ]),
      ),
    },
  },
  test: {
    include: ["test/contracts/safr-pr00/*.test.ts", "test/unit/**/*.test.ts"],
    testTimeout: 15000,
  },
});
