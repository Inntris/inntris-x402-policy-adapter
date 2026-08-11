CREATE TABLE inntris.execution_operations (
  operation_id text PRIMARY KEY,
  rail text NOT NULL,
  operation_kind text NOT NULL,
  decision_id text NOT NULL,
  action_hash text NOT NULL,
  execution_ref text NOT NULL,
  binding_hash text NOT NULL,
  status text NOT NULL,
  attempt_count integer NOT NULL DEFAULT 0,
  prepared_at timestamptz NOT NULL,
  started_at timestamptz,
  updated_at timestamptz NOT NULL,
  resolved_at timestamptz,
  outcome_reference text,
  last_error_code text,
  resolved_by text,
  resolution_note text,
  CONSTRAINT execution_operations_status_check CHECK (
    status IN ('prepared', 'in_progress', 'succeeded', 'failed_final', 'outcome_unknown')
  ),
  CONSTRAINT execution_operations_kind_check CHECK (
    operation_kind IN (
      'x402_settlement', 'a2a_settlement', 'a2a_delegate',
      'ap2_delegate', 'evm_broadcast', 'mtp_consumption'
    )
  ),
  CONSTRAINT execution_operations_attempt_count_check CHECK (attempt_count >= 0),
  CONSTRAINT execution_operations_execution_ref_check CHECK (
    length(execution_ref) BETWEEN 1 AND 512
  ),
  CONSTRAINT execution_operations_unique_reference UNIQUE (rail, operation_kind, execution_ref)
);

CREATE INDEX execution_operations_unresolved_idx
  ON inntris.execution_operations (updated_at, operation_id)
  WHERE status IN ('in_progress', 'outcome_unknown');
