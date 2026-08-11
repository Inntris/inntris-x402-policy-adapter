# `@inntris/postgres-store`

Durable PostgreSQL state for the local Inntris policy provider.

The store persists immutable signed decisions, atomically claims human approvals and commits
decision consumption with its cumulative spend increment in one database transaction. The daily
limit is rechecked under the database write lock, so concurrent decisions cannot overrun it.

It also supplies `PostgresMtpAuthorityStateStore` for the cross-service MTP bridge. That store
persists authority before a decision is returned, claims one stable execution reference, checkpoints
the MTP consumption receipt and records completion of local decision consumption.

`PostgresExecutionReconciliationStore` supplies durable side-effect state. It binds a stable
execution reference to the rail, operation kind, decision and action, atomically claims one attempt,
records an unknown outcome without retrying and accepts evidence-bearing authoritative resolution.

```ts
import { Pool } from "pg";
import {
  PostgresExecutionReconciliationStore,
  PostgresPolicyStateStore,
  migratePostgresStore,
} from "@inntris/postgres-store";

const pool = new Pool({ connectionString: process.env.INNTRIS_POSTGRES_URL });
await migratePostgresStore(pool);

const stateStore = new PostgresPolicyStateStore(pool);
const reconciliationStore = new PostgresExecutionReconciliationStore(pool);
const provider = new LocalPolicyDecisionProvider({ policy, signer, stateStore });
```

Apply migrations before the service starts:

```bash
INNTRIS_POSTGRES_URL=postgresql://... pnpm postgres:migrate
```

When `INNTRIS_POSTGRES_URL` is set, `@inntris/demo-api` requires every migration and injects the
durable policy and reconciliation stores automatically. It also requires `INNTRIS_SERVICE_API_KEY`
before exposing the authenticated unresolved-operation queue. Enabling `INNTRIS_MTP_API_URL`
additionally injects the durable MTP bridge and refuses to start without PostgreSQL. Without those
settings the service retains the in-memory demo behaviour.

The caller owns the pool and must close it during shutdown. Use a dedicated database role whose
permissions are limited to the `inntris` schema. Run migrations with a separate deployment role when
runtime schema creation is not permitted.

The MTP approval token is short lived but remains bearer authority until consumed. Limit table
access to the runtime role, protect database backups and never include table rows in normal logs.
`INNTRIS_POSTGRES_URL` is used by the repository integration tests. It is never logged.

See [`docs/RECONCILIATION.md`](../../docs/RECONCILIATION.md) for the state model, failure matrix and
operator procedure.
