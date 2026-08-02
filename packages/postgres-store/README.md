# `@inntris/postgres-store`

Durable PostgreSQL state for the local Inntris policy provider.

The store persists immutable signed decisions, atomically claims human approvals and commits
decision consumption with its cumulative spend increment in one database transaction. The daily
limit is rechecked under the database write lock, so concurrent decisions cannot overrun it.

```ts
import { Pool } from "pg";
import { PostgresPolicyStateStore, migratePostgresStore } from "@inntris/postgres-store";

const pool = new Pool({ connectionString: process.env.INNTRIS_POSTGRES_URL });
await migratePostgresStore(pool);

const stateStore = new PostgresPolicyStateStore(pool);
const provider = new LocalPolicyDecisionProvider({ policy, signer, stateStore });
```

Apply migrations before the service starts:

```bash
INNTRIS_POSTGRES_URL=postgresql://... pnpm postgres:migrate
```

When `INNTRIS_POSTGRES_URL` is set, `@inntris/demo-api` requires the migration and injects the
durable store automatically. Without that setting it retains the in-memory demo behaviour.

The caller owns the pool and must close it during shutdown. Use a dedicated database role whose
permissions are limited to the `inntris` schema. Run migrations with a separate deployment role when
runtime schema creation is not permitted.

`INNTRIS_POSTGRES_URL` is used by the repository integration tests. It is never logged.
