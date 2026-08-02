import { readFile } from "node:fs/promises";

import type { Pool } from "pg";

const MIGRATION_VERSION = "001_initial";
const MIGRATION_LOCK_ID = 1_661_437_315;

export async function assertPostgresStoreReady(pool: Pool): Promise<void> {
  const table = await pool.query<{ relation: string | null }>(
    "SELECT to_regclass('inntris.schema_migrations')::text AS relation",
  );
  if (table.rows[0]?.relation === null) {
    throw new Error("Inntris PostgreSQL migrations have not been applied");
  }
  const applied = await pool.query<{ version: string }>(
    "SELECT version FROM inntris.schema_migrations WHERE version = $1",
    [MIGRATION_VERSION],
  );
  if (applied.rowCount !== 1) {
    throw new Error(`Required Inntris PostgreSQL migration ${MIGRATION_VERSION} is missing`);
  }
}

export async function migratePostgresStore(pool: Pool): Promise<void> {
  const sql = await readFile(
    new URL(`../migrations/${MIGRATION_VERSION}.sql`, import.meta.url),
    "utf8",
  );
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
    const applied = await client.query<{ version: string }>(
      "SELECT version FROM inntris.schema_migrations WHERE version = $1",
      [MIGRATION_VERSION],
    );
    if (applied.rowCount === 0) {
      await client.query(sql);
      await client.query("INSERT INTO inntris.schema_migrations (version) VALUES ($1)", [
        MIGRATION_VERSION,
      ]);
    }
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}
