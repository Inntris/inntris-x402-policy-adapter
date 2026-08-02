#!/usr/bin/env node

import { Pool } from "pg";

import { migratePostgresStore } from "./migrate.js";

const connectionString = process.env.INNTRIS_POSTGRES_URL?.trim();
if (connectionString === undefined || connectionString === "") {
  throw new Error("INNTRIS_POSTGRES_URL is required");
}

const pool = new Pool({ connectionString });
try {
  await migratePostgresStore(pool);
  process.stdout.write("Inntris PostgreSQL migrations applied successfully\n");
} finally {
  await pool.end();
}
