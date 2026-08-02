CREATE TABLE inntris.decisions (
  decision_id text PRIMARY KEY,
  decision jsonb NOT NULL CHECK (jsonb_typeof(decision) = 'object'),
  action jsonb NOT NULL CHECK (jsonb_typeof(action) = 'object'),
  saved_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE inntris.approval_claims (
  decision_id text PRIMARY KEY REFERENCES inntris.decisions(decision_id) ON DELETE RESTRICT,
  claimed_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE inntris.consumptions (
  decision_id text PRIMARY KEY REFERENCES inntris.decisions(decision_id) ON DELETE RESTRICT,
  nonce text NOT NULL UNIQUE,
  action_hash text NOT NULL,
  execution_ref text NOT NULL,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz NOT NULL
);

CREATE INDEX consumptions_execution_ref_idx
  ON inntris.consumptions (execution_ref);

CREATE TABLE inntris.daily_spend (
  principal_id text NOT NULL,
  day_key text NOT NULL,
  amount numeric NOT NULL CHECK (amount >= 0),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (principal_id, day_key),
  CHECK (day_key ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$')
);
