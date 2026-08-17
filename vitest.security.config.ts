import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/security/**/*.test.ts"],
    testTimeout: 15_000,
    /**
     * The suite writes a single shared evidence report, so the files that
     * contribute to it must not run in parallel processes.
     */
    fileParallelism: false,
  },
});
