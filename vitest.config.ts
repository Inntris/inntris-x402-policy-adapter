import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    coverage: {
      enabled: false,
    },
    include: ["**/*.test.ts"],
    testTimeout: 15_000,
  },
});
