import {
  InntrisActionV1Schema,
  InntrisDecisionV1Schema,
  KeyRegistrySchema,
  calculateDecisionFingerprint,
  hashAction,
  hashCanonical,
  publicKeyFingerprint,
  verifyDecisionSignature,
  type InntrisActionV1,
  type InntrisDecisionV1,
  type KeyRegistry,
  type ReasonCode,
  type Verdict,
} from "@inntris/decision-core";

export interface VerificationChecks {
  schema: boolean;
  signature: boolean;
  fingerprint: boolean;
  action_hash: boolean;
  decision_binding: boolean;
  expiry: boolean;
  policy_version: boolean;
  payment_requirements: boolean;
}

export interface VerificationResult {
  valid: boolean;
  verdict?: Verdict;
  decision_id?: string;
  checks: VerificationChecks;
  reason_codes: ReasonCode[];
}

export interface VerifyDecisionInput {
  decision: unknown;
  action: unknown;
  keyRegistry: unknown;
  at?: Date | undefined;
  expectedPolicyVersion?: string | undefined;
  expectedPaymentRequirementsHash?: string | undefined;
}

function emptyChecks(): VerificationChecks {
  return {
    schema: false,
    signature: false,
    fingerprint: false,
    action_hash: false,
    decision_binding: false,
    expiry: false,
    policy_version: false,
    payment_requirements: false,
  };
}

/**
 * The signed decision restates the subject it decided on. A correct issuer
 * always restates the same action it hashed, so a mismatch means the decision
 * is internally inconsistent even when its signature is genuine.
 */
function bindsSuppliedAction(decision: InntrisDecisionV1, action: InntrisActionV1): boolean {
  return (
    decision.principal_id === action.principal_id &&
    decision.agent_id === action.agent_id &&
    decision.action_type === action.action_type &&
    decision.rail === action.rail &&
    hashCanonical(decision.transaction) === hashCanonical(action.transaction) &&
    hashCanonical(decision.protocol_reference) === hashCanonical(action.protocol_reference)
  );
}

function addReason(reasons: ReasonCode[], reason: ReasonCode): void {
  if (!reasons.includes(reason)) {
    reasons.push(reason);
  }
}

function findUsableKey(
  decision: InntrisDecisionV1,
  registry: KeyRegistry,
): { publicKey: Uint8Array } | null {
  const key = registry.keys.find((entry) => entry.key_id === decision.signing.key_id);
  if (key === undefined || key.status === "revoked" || key.alg !== decision.signing.alg) {
    return null;
  }
  const issuedAt = Date.parse(decision.issued_at);
  if (
    issuedAt < Date.parse(key.not_before) ||
    (key.not_after !== null && issuedAt >= Date.parse(key.not_after))
  ) {
    return null;
  }
  const publicKey = Buffer.from(key.public_key, "base64url");
  if (publicKey.byteLength !== 32 || publicKeyFingerprint(publicKey) !== key.fingerprint) {
    return null;
  }
  return { publicKey };
}

export interface SignedDecisionVerificationResult {
  valid: boolean;
  checks: { schema: boolean; fingerprint: boolean; signature: boolean };
  reason_codes: ReasonCode[];
}

/**
 * Verifies only that a decision is a well-formed, untampered, correctly signed
 * envelope. Callers that hold the original action should use `verifyDecision`,
 * which additionally proves the decision is bound to that exact action.
 */
export function verifySignedDecision(
  decisionInput: unknown,
  keyRegistryInput: unknown,
): SignedDecisionVerificationResult {
  const checks = { schema: false, fingerprint: false, signature: false };
  const reasonCodes: ReasonCode[] = [];
  const parsedDecision = InntrisDecisionV1Schema.safeParse(decisionInput);
  const parsedRegistry = KeyRegistrySchema.safeParse(keyRegistryInput);
  if (!parsedDecision.success || !parsedRegistry.success) {
    return { valid: false, checks, reason_codes: ["INVALID_DECISION_SCHEMA"] };
  }
  checks.schema = true;
  const decision = parsedDecision.data;

  checks.fingerprint = calculateDecisionFingerprint(decision) === decision.decision_fingerprint;
  if (!checks.fingerprint) {
    addReason(reasonCodes, "FINGERPRINT_MISMATCH");
  }

  const key = findUsableKey(decision, parsedRegistry.data);
  if (key === null) {
    addReason(reasonCodes, "UNKNOWN_SIGNING_KEY");
  } else {
    checks.signature = verifyDecisionSignature(decision, key.publicKey);
    if (!checks.signature) {
      addReason(reasonCodes, "INVALID_SIGNATURE");
    }
  }

  return {
    valid: Object.values(checks).every(Boolean),
    checks,
    reason_codes: reasonCodes,
  };
}

export function verifyDecision(input: VerifyDecisionInput): VerificationResult {
  const checks = emptyChecks();
  const reasonCodes: ReasonCode[] = [];
  const parsedDecision = InntrisDecisionV1Schema.safeParse(input.decision);
  const parsedAction = InntrisActionV1Schema.safeParse(input.action);
  const parsedRegistry = KeyRegistrySchema.safeParse(input.keyRegistry);

  if (!parsedDecision.success || !parsedAction.success || !parsedRegistry.success) {
    return {
      valid: false,
      checks,
      reason_codes: ["INVALID_DECISION_SCHEMA"],
    };
  }

  checks.schema = true;
  const decision = parsedDecision.data;
  const action: InntrisActionV1 = parsedAction.data;
  const registry = parsedRegistry.data;

  checks.fingerprint = calculateDecisionFingerprint(decision) === decision.decision_fingerprint;
  if (!checks.fingerprint) {
    addReason(reasonCodes, "FINGERPRINT_MISMATCH");
  }

  const key = findUsableKey(decision, registry);
  if (key === null) {
    addReason(reasonCodes, "UNKNOWN_SIGNING_KEY");
  } else {
    checks.signature = verifyDecisionSignature(decision, key.publicKey);
    if (!checks.signature) {
      addReason(reasonCodes, "INVALID_SIGNATURE");
    }
  }

  checks.action_hash = hashAction(action) === decision.action_hash;
  if (!checks.action_hash) {
    addReason(reasonCodes, "ACTION_HASH_MISMATCH");
  }

  checks.decision_binding = bindsSuppliedAction(decision, action);
  if (!checks.decision_binding) {
    addReason(reasonCodes, "DECISION_BINDING_MISMATCH");
  }

  const at = input.at ?? new Date();
  checks.expiry =
    at.getTime() >= Date.parse(decision.issued_at) &&
    at.getTime() < Date.parse(decision.expires_at);
  if (!checks.expiry) {
    addReason(reasonCodes, "DECISION_EXPIRED");
  }

  checks.policy_version =
    input.expectedPolicyVersion === undefined ||
    decision.policy.policy_version === input.expectedPolicyVersion;
  if (!checks.policy_version) {
    addReason(reasonCodes, "POLICY_VERSION_MISMATCH");
  }

  checks.payment_requirements =
    input.expectedPaymentRequirementsHash === undefined ||
    (decision.protocol_reference.type === "x402" &&
      decision.protocol_reference.payment_requirements_hash ===
        input.expectedPaymentRequirementsHash);
  if (!checks.payment_requirements) {
    addReason(reasonCodes, "PAYMENT_REQUIREMENTS_MISMATCH");
  }

  return {
    valid: Object.values(checks).every(Boolean),
    verdict: decision.verdict,
    decision_id: decision.decision_id,
    checks,
    reason_codes: reasonCodes,
  };
}

export function humanVerificationOutput(result: VerificationResult): string {
  const lines = [
    `${result.checks.schema ? "PASS" : "FAIL"} schema`,
    `${result.checks.fingerprint ? "PASS" : "FAIL"} decision fingerprint`,
    `${result.checks.signature ? "PASS" : "FAIL"} Ed25519 signature`,
    `${result.checks.action_hash ? "PASS" : "FAIL"} action hash`,
    `${result.checks.decision_binding ? "PASS" : "FAIL"} decision binds the supplied action`,
    `${result.checks.expiry ? "PASS" : "FAIL"} decision expiry at supplied execution time`,
    `${result.checks.policy_version ? "PASS" : "FAIL"} policy version`,
    `${result.checks.payment_requirements ? "PASS" : "FAIL"} x402 payment-requirements binding`,
    "",
    `VERDICT: ${result.verdict ?? "UNKNOWN"}`,
    `DECISION: ${result.valid ? "VALID" : "INVALID"}`,
  ];
  if (result.reason_codes.length > 0) {
    lines.push(`REASONS: ${result.reason_codes.join(", ")}`);
  }
  return lines.join("\n");
}
