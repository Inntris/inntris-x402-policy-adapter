import { readFile } from "node:fs/promises";

import type { Pool } from "pg";

const MIGRATION_VERSIONS = ["001_initial", "002_mtp_authority"] as const;
const MIGRATION_LOCK_ID = 1_661_437_315;

export async function assertPostgresStoreReady(pool: Pool): Promise<void> {
  const table = await pool.query<{ relation: string | null }>(
    "SELECT to_regclass('inntris.schema_migrations')::text AS relation",
  );
  if (table.rows[0]?.relation === null) {
    throw new Error("Inntris PostgreSQL migrations have not been applied");
  }
  const applied = await pool.query<{ version: string }>(
    "SELECT version FROM inntris.schema_migrations WHERE version = ANY($1::text[])",
    [MIGRATION_VERSIONS],
  );
  const appliedVersions = new Set(applied.rows.map((row) => row.version));
  const missing = MIGRATION_VERSIONS.filter((version) => !appliedVersions.has(version));
  if (missing.length > 0) {
    throw new Error(`Required Inntris PostgreSQL migrations are missing: ${missing.join(", ")}`);
  }
}

export async function migratePostgresStore(pool: Pool): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock($1)", [MIGRATION_LOCK_ID]);
    await client.query("CREATE SCHEMA IF NOT EXISTS inntris");
    await client.query(`
      CREATE TABLE IF NOT EXISTS inntris.schema_migrations (
        version text PRIMARY KEY,
        applied_at timestamptz NOT NULL DEFAULT now()
      )
    `);
    for (const version of MIGRATION_VERSIONS) {
      const applied = await client.query<{ version: string }>(
        "SELECT version FROM inntris.schema_migrations WHERE version = $1",
        [version],
      );
      if (applied.rowCount === 0) {
        const sql = await readFile(
          new URL(`../migrations/${version}.sql`, import.meta.url),
          "utf8",
        );
        await client.query(sql);
        await client.query("INSERT INTO inntris.schema_migrations (version) VALUES ($1)", [
          version,
        ]);
      }
    }
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}
