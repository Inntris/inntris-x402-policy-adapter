CREATE TABLE inntris.mtp_authorisations (
  decision_id text PRIMARY KEY,
  action_hash text NOT NULL CHECK (action_hash ~ '^sha256:[0-9a-f]{64}$'),
  mtp_agent_id uuid NOT NULL,
  verify_request jsonb NOT NULL CHECK (jsonb_typeof(verify_request) = 'object'),
  mtp_action_hash text NOT NULL CHECK (mtp_action_hash ~ '^[0-9a-f]{64}$'),
  approval_token text NOT NULL CHECK (length(approval_token) > 0),
  authorization_audit_id uuid NOT NULL,
  authorized_at timestamptz NOT NULL,
  execution_ref text,
  consumption_audit_id uuid,
  consumption_status text CHECK (consumption_status IN ('consumed', 'idempotent')),
  completed_at timestamptz,
  saved_at timestamptz NOT NULL DEFAULT now(),
  CHECK (execution_ref IS NULL OR (length(btrim(execution_ref)) > 0 AND length(execution_ref) <= 512)),
  CHECK (
    (consumption_audit_id IS NULL AND consumption_status IS NULL)
    OR (consumption_audit_id IS NOT NULL AND consumption_status IS NOT NULL)
  ),
  CHECK (completed_at IS NULL OR consumption_audit_id IS NOT NULL)
);

CREATE UNIQUE INDEX mtp_authorisations_execution_ref_idx
  ON inntris.mtp_authorisations (mtp_agent_id, execution_ref)
  WHERE execution_ref IS NOT NULL;

COMMENT ON TABLE inntris.mtp_authorisations IS
  'Durable cross-service state binding one signed Inntris decision to MTP execution authority.';

COMMENT ON COLUMN inntris.mtp_authorisations.approval_token IS
  'Short-lived MTP bearer token. Restrict table access and never emit this value to logs.';
