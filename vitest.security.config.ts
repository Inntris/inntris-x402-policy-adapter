import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/security/**/*.test.ts"],
    testTimeout: 30_000,
    globalSetup: ["test/security/global-setup.ts"],
    /**
     * Each file writes its own evidence shard, and the shards are merged in
     * global teardown. Serial execution keeps the merged bundle deterministic.
     */
    fileParallelism: false,
    sequence: { shuffle: false },
  },
});
