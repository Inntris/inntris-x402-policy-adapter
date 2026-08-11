CREATE TABLE inntris.kya_proof_nonces (
  did text NOT NULL,
  nonce text NOT NULL,
  consumed_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (did, nonce),
  CHECK (length(did) > 0),
  CHECK (length(nonce) > 0),
  CHECK (expires_at > consumed_at)
);

CREATE INDEX kya_proof_nonces_expires_at_idx
  ON inntris.kya_proof_nonces (expires_at);

CREATE TABLE inntris.kya_authority_decisions (
  decision_id text PRIMARY KEY REFERENCES inntris.decisions(decision_id) ON DELETE RESTRICT,
  action_hash text NOT NULL CHECK (action_hash ~ '^sha256:[0-9a-f]{64}$'),
  action_json jsonb NOT NULL CHECK (jsonb_typeof(action_json) = 'object'),
  binding_json jsonb NOT NULL CHECK (jsonb_typeof(binding_json) = 'object'),
  authority_hash text NOT NULL CHECK (authority_hash ~ '^sha256:[0-9a-f]{64}$'),
  authority_policy_hash text NOT NULL CHECK (authority_policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  presentation_hash text NOT NULL CHECK (presentation_hash ~ '^sha256:[0-9a-f]{64}$'),
  proof_hash text CHECK (proof_hash ~ '^sha256:[0-9a-f]{64}$'),
  delegation_chain_hash text CHECK (delegation_chain_hash ~ '^sha256:[0-9a-f]{64}$'),
  agent_did text,
  responsible_party_did text,
  authority_expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE inntris.kya_authority_revalidations (
  id uuid PRIMARY KEY,
  decision_id text NOT NULL REFERENCES inntris.kya_authority_decisions(decision_id) ON DELETE RESTRICT,
  action_hash text NOT NULL CHECK (action_hash ~ '^sha256:[0-9a-f]{64}$'),
  kind text NOT NULL CHECK (kind IN ('approval', 'consumption')),
  execution_ref text,
  approval_reference text,
  presentation_hash text NOT NULL CHECK (presentation_hash ~ '^sha256:[0-9a-f]{64}$'),
  authority_hash text CHECK (authority_hash ~ '^sha256:[0-9a-f]{64}$'),
  status text NOT NULL CHECK (status IN ('verified', 'rejected')),
  reason_code text,
  verified_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK ((kind = 'consumption') = (execution_ref IS NOT NULL)),
  CHECK ((kind = 'approval') = (approval_reference IS NOT NULL)),
  CHECK ((status = 'verified' AND authority_hash IS NOT NULL AND reason_code IS NULL)
    OR (status = 'rejected' AND authority_hash IS NULL AND reason_code IS NOT NULL))
);

CREATE UNIQUE INDEX kya_consumption_revalidation_idempotency_idx
  ON inntris.kya_authority_revalidations (decision_id, action_hash, execution_ref, kind)
  WHERE kind = 'consumption' AND status = 'verified';

CREATE INDEX kya_authority_revalidations_decision_idx
  ON inntris.kya_authority_revalidations (decision_id, verified_at);

COMMENT ON TABLE inntris.kya_proof_nonces IS
  'Atomic replay state for short-lived KYA holder-of-key request proofs.';

COMMENT ON TABLE inntris.kya_authority_decisions IS
  'Immutable minimised KYA authority bound to an Inntris decision and action.';

COMMENT ON TABLE inntris.kya_authority_revalidations IS
  'Append-only KYA approval and consumption revalidation history.';
