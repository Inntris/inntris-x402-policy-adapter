import {
  InntrisActionV1Schema,
  InntrisDecisionV1Schema,
  InMemoryMetrics,
  type Clock,
  type DecisionProvider,
  type KeyRegistry,
  type MetricsRecorder,
} from "@inntris/decision-core";
import { verifyDecision } from "@inntris/decision-verifier";
import type { ExecutionReconciliationStore } from "@inntris/execution-reconciliation";
import {
  hashKyaAuthorityPolicy,
  KyaAuthorityPresentationSchema,
  type KyaAuthorityPolicyV1,
  type KyaConsumeInput,
  type KyaEvaluateInput,
  type KyaResolveApprovalInput,
} from "@inntris/kya-os-authority";
import {
  actionFromKyaX402,
  type PaymentPayload,
  type PaymentRequirements,
} from "@inntris/x402-adapter";
import rateLimit from "@fastify/rate-limit";
import { timingSafeEqual } from "node:crypto";
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from "fastify";
import { z } from "zod";

const EvaluateBodySchema = z.object({ action: InntrisActionV1Schema }).strict();
const VerifyBodySchema = z
  .object({
    decision: InntrisDecisionV1Schema,
    action: InntrisActionV1Schema,
    expected_policy_version: z.string().optional(),
  })
  .strict();
const ConsumeBodySchema = z
  .object({
    decision_id: z.string().min(1),
    action_hash: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
    execution_ref: z.string().min(1).max(512),
  })
  .strict();
const ApproveBodySchema = z
  .object({
    decision_id: z.string().min(1),
    granted: z.boolean(),
    approval_reference: z.string().min(1).max(256),
    approver_ids: z.array(z.string().min(1).max(128)).min(1).max(32),
  })
  .strict();
const KyaX402EvaluateBodySchema = z
  .object({
    payment_requirements: z.unknown(),
    payment_payload: z.unknown().optional(),
    resource: z.url(),
    purpose: z.string().min(1).max(128),
    asset_decimals: z.number().int().min(0).max(18),
    presentation: KyaAuthorityPresentationSchema,
    extensions: z.record(z.string(), z.unknown()).optional(),
  })
  .strict();
const KyaApproveBodySchema = ApproveBodySchema.extend({
  presentation: KyaAuthorityPresentationSchema,
}).strict();
const KyaConsumeBodySchema = ConsumeBodySchema.extend({
  presentation: KyaAuthorityPresentationSchema,
}).strict();
const ReconciliationQuerySchema = z
  .object({
    updated_before: z.iso.datetime({ offset: true }).optional(),
    limit: z.coerce.number().int().min(1).max(500).optional(),
  })
  .strict();

export interface DemoApiOptions {
  provider: DecisionProvider;
  keyRegistry: KeyRegistry;
  expectedPolicyVersion?: string | undefined;
  serviceApiKey?: string | undefined;
  metrics?: MetricsRecorder | undefined;
  clock?: Clock | undefined;
  logger?: boolean | undefined;
  reconciliationStore?: ExecutionReconciliationStore | undefined;
  kya?:
    | {
        mode: "optional" | "required";
        policy: KyaAuthorityPolicyV1;
        gate: {
          evaluate(
            input: KyaEvaluateInput,
          ): Promise<import("@inntris/decision-core").InntrisDecisionV1>;
          resolveApproval(
            input: KyaResolveApprovalInput,
          ): Promise<import("@inntris/decision-core").ResolveApprovalResult>;
          consume(
            input: KyaConsumeInput,
          ): Promise<import("@inntris/decision-core").ConsumeDecisionResult>;
          protectsDecision(decisionId: string): Promise<boolean>;
        };
      }
    | undefined;
}

function parseFailure(reply: FastifyReply, error: unknown): void {
  reply.status(400).send({
    error: "malformed_input",
    message: error instanceof Error ? error.message : "Input validation failed",
  });
}

function bearerMatches(actual: string | undefined, expectedKey: string): boolean {
  const actualBytes = Buffer.from(actual ?? "", "utf8");
  const expectedBytes = Buffer.from(`Bearer ${expectedKey}`, "utf8");
  return actualBytes.length === expectedBytes.length && timingSafeEqual(actualBytes, expectedBytes);
}

export async function buildDemoApi(options: DemoApiOptions): Promise<FastifyInstance> {
  if (options.reconciliationStore !== undefined && options.serviceApiKey === undefined) {
    throw new Error("A service API key is required when operational reconciliation is exposed");
  }
  const app = Fastify({
    logger: options.logger ?? true,
  });
  const metrics = options.metrics ?? new InMemoryMetrics();
  const clock = options.clock ?? { now: () => new Date() };

  const authenticate = async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    if (options.serviceApiKey === undefined) {
      return;
    }
    if (!bearerMatches(request.headers.authorization, options.serviceApiKey)) {
      await reply.status(401).send({ error: "authentication_failed" });
    }
  };

  await app.register(rateLimit, {
    global: true,
    max: 100,
    timeWindow: "1 minute",
  });

  app.get("/healthz", async () => ({
    status: "ok",
    service: "inntris-decision-reference",
  }));

  app.get("/.well-known/inntris-keys.json", async () => options.keyRegistry);

  app.get(
    "/v1/kya/config",
    { config: { rateLimit: { max: 30, timeWindow: "1 minute" } } },
    async () => {
      if (options.kya === undefined) return { enabled: false };
      return {
        enabled: true,
        mode: options.kya.mode,
        authority_policy: {
          policy_id: options.kya.policy.policy_id,
          policy_version: options.kya.policy.policy_version,
          policy_hash: hashKyaAuthorityPolicy(options.kya.policy),
          profiles: options.kya.policy.profiles,
          accepted_did_methods: options.kya.policy.accepted_did_methods,
          min_proof_assurance: options.kya.policy.min_proof_assurance,
          require_fresh_revocation: options.kya.policy.require_fresh_revocation,
        },
      };
    },
  );

  app.get(
    "/v1/operations/unresolved",
    {
      preHandler: authenticate,
      config: { rateLimit: { max: 30, timeWindow: "1 minute" } },
    },
    async (request, reply) => {
      if (options.reconciliationStore === undefined) {
        await reply.status(503).send({ error: "reconciliation_store_unavailable" });
        return;
      }
      let query: z.infer<typeof ReconciliationQuerySchema>;
      try {
        query = ReconciliationQuerySchema.parse(request.query);
      } catch (error) {
        parseFailure(reply, error);
        return;
      }
      try {
        const operations = await options.reconciliationStore.listUnresolved({
          ...(query.updated_before === undefined
            ? {}
            : { updatedBefore: new Date(query.updated_before) }),
          ...(query.limit === undefined ? {} : { limit: query.limit }),
        });
        request.log.info({
          request_id: request.id,
          unresolved_operation_count: operations.length,
        });
        await reply.status(200).send({ operations });
      } catch {
        await reply.status(503).send({ error: "reconciliation_store_unavailable" });
      }
    },
  );

  app.post(
    "/v1/decisions/evaluate",
    {
      preHandler: authenticate,
      config: { rateLimit: { max: 30, timeWindow: "1 minute" } },
    },
    async (request, reply) => {
      const started = performance.now();
      let body: z.infer<typeof EvaluateBodySchema>;
      try {
        body = EvaluateBodySchema.parse(request.body);
      } catch (error) {
        parseFailure(reply, error);
        return;
      }
      try {
        const kya = options.kya;
        const protectedByRequiredKya =
          kya?.mode === "required" &&
          kya.policy.resource_bindings.some(
            (binding) => binding.inntris_resource === body.action.protocol_reference.resource,
          );
        const decision =
          protectedByRequiredKya && kya !== undefined
            ? await kya.gate.evaluate({ action: body.action })
            : await options.provider.evaluate(body.action);
        request.log.info({
          request_id: request.id,
          decision_id: decision.decision_id,
          verdict: decision.verdict,
          rail: decision.rail,
          reason_codes: decision.reason_codes,
          evaluation_latency_ms: performance.now() - started,
        });
        await reply.status(200).send({ decision });
      } catch {
        await reply.status(503).send({
          error: "decision_service_unavailable",
        });
      }
    },
  );

  app.post(
    "/v1/kya/x402/evaluate",
    {
      preHandler: authenticate,
      config: { rateLimit: { max: 30, timeWindow: "1 minute" } },
    },
    async (request, reply) => {
      if (options.kya === undefined) {
        await reply.status(503).send({ error: "kya_authority_disabled" });
        return;
      }
      let body: z.infer<typeof KyaX402EvaluateBodySchema>;
      try {
        body = KyaX402EvaluateBodySchema.parse(request.body);
      } catch (error) {
        parseFailure(reply, error);
        return;
      }
      let action;
      try {
        action = actionFromKyaX402(
          {
            paymentRequirements: body.payment_requirements as PaymentRequirements,
            ...(body.payment_payload === undefined
              ? {}
              : { paymentPayload: body.payment_payload as PaymentPayload }),
            resource: body.resource,
            purpose: body.purpose,
            assetDecimals: body.asset_decimals,
            presentation: body.presentation,
            ...(body.extensions === undefined ? {} : { extensions: body.extensions }),
          },
          options.kya.policy,
        );
      } catch (error) {
        parseFailure(reply, error);
        return;
      }
      try {
        const decision = await options.kya.gate.evaluate({
          action,
          presentation: body.presentation,
        });
        await reply.status(200).send({ decision });
      } catch {
        await reply.status(503).send({ error: "kya_authority_state_unavailable" });
      }
    },
  );

  app.post(
    "/v1/kya/decisions/approve",
    {
      preHandler: authenticate,
      config: { rateLimit: { max: 30, timeWindow: "1 minute" } },
    },
    async (request, reply) => {
      if (options.kya === undefined) {
        await reply.status(503).send({ error: "kya_authority_disabled" });
        return;
      }
      let body: z.infer<typeof KyaApproveBodySchema>;
      try {
        body = KyaApproveBodySchema.parse(request.body);
      } catch (error) {
        parseFailure(reply, error);
        return;
      }
      const { presentation, ...approval } = body;
      let result;
      try {
        result = await options.kya.gate.resolveApproval({ approval, presentation });
      } catch {
        await reply.status(503).send({ error: "kya_authority_state_unavailable" });
        return;
      }
      await reply
        .status(result.success ? 200 : result.status === "conflict" ? 409 : 422)
        .send(result);
    },
  );

  app.post(
    "/v1/kya/decisions/consume",
    {
      preHandler: authenticate,
      config: { rateLimit: { max: 30, timeWindow: "1 minute" } },
    },
    async (request, reply) => {
      if (options.kya === undefined) {
        await reply.status(503).send({ error: "kya_authority_disabled" });
        return;
      }
      let body: z.infer<typeof KyaConsumeBodySchema>;
      try {
        body = KyaConsumeBodySchema.parse(request.body);
      } catch (error) {
        parseFailure(reply, error);
        return;
      }
      const { presentation, ...consumption } = body;
      let result;
      try {
        result = await options.kya.gate.consume({ consumption, presentation });
      } catch {
        await reply.status(503).send({ error: "kya_authority_state_unavailable" });
        return;
      }
      await reply
        .status(result.status === "conflict" ? 409 : result.success ? 200 : 422)
        .send(result);
    },
  );

  app.post(
    "/v1/decisions/verify",
    {
      preHandler: authenticate,
      config: { rateLimit: { max: 30, timeWindow: "1 minute" } },
    },
    async (request, reply) => {
      let body: z.infer<typeof VerifyBodySchema>;
      try {
        body = VerifyBodySchema.parse(request.body);
      } catch (error) {
        parseFailure(reply, error);
        return;
      }
      const result = verifyDecision({
        decision: body.decision,
        action: body.action,
        keyRegistry: options.keyRegistry,
        at: clock.now(),
        expectedPolicyVersion: body.expected_policy_version ?? options.expectedPolicyVersion,
      });
      for (const reason of result.reason_codes) {
        metrics.verificationFailure(reason);
      }
      request.log.info({
        request_id: request.id,
        decision_id: body.decision.decision_id,
        verification_result: result.valid,
        reason_codes: result.reason_codes,
      });
      await reply.status(200).send(result);
    },
  );

  app.post(
    "/v1/decisions/approve",
    {
      preHandler: authenticate,
      config: { rateLimit: { max: 30, timeWindow: "1 minute" } },
    },
    async (request, reply) => {
      let body: z.infer<typeof ApproveBodySchema>;
      try {
        body = ApproveBodySchema.parse(request.body);
      } catch (error) {
        parseFailure(reply, error);
        return;
      }
      if (options.provider.resolveApproval === undefined) {
        await reply.status(503).send({ error: "approval_service_unavailable" });
        return;
      }
      let result;
      try {
        if (await options.kya?.gate.protectsDecision(body.decision_id)) {
          await reply.status(422).send({
            success: false,
            status: "rejected",
            decision_id: body.decision_id,
            reason_code: "KYA_AUTHORITY_REQUIRED",
          });
          return;
        }
        result = await options.provider.resolveApproval(body);
      } catch {
        await reply.status(503).send({ error: "approval_service_unavailable" });
        return;
      }
      request.log.info({
        request_id: request.id,
        decision_id: body.decision_id,
        approval_result: result.status,
        superseding_decision_id: result.decision?.decision_id,
        verdict: result.decision?.verdict,
        reason_codes: result.reason_code === undefined ? [] : [result.reason_code],
      });
      const statusCode = result.success ? 200 : result.status === "conflict" ? 409 : 422;
      await reply.status(statusCode).send(result);
    },
  );

  app.post(
    "/v1/decisions/consume",
    {
      preHandler: authenticate,
      config: { rateLimit: { max: 30, timeWindow: "1 minute" } },
    },
    async (request, reply) => {
      let body: z.infer<typeof ConsumeBodySchema>;
      try {
        body = ConsumeBodySchema.parse(request.body);
      } catch (error) {
        parseFailure(reply, error);
        return;
      }
      let result;
      try {
        if (await options.kya?.gate.protectsDecision(body.decision_id)) {
          await reply.status(422).send({
            success: false,
            status: "rejected",
            decision_id: body.decision_id,
            execution_ref: body.execution_ref,
            reason_code: "KYA_AUTHORITY_REQUIRED",
          });
          return;
        }
        result = await options.provider.consume(body);
      } catch {
        await reply.status(503).send({ error: "consumption_service_unavailable" });
        return;
      }
      request.log.info({
        request_id: request.id,
        decision_id: body.decision_id,
        consumption_result: result.status,
        reason_codes: result.reason_code === undefined ? [] : [result.reason_code],
      });
      const statusCode = result.status === "conflict" ? 409 : result.success ? 200 : 422;
      await reply.status(statusCode).send(result);
    },
  );

  return app;
}
