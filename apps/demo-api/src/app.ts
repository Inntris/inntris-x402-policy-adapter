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

export interface DemoApiOptions {
  provider: DecisionProvider;
  keyRegistry: KeyRegistry;
  expectedPolicyVersion?: string | undefined;
  serviceApiKey?: string | undefined;
  metrics?: MetricsRecorder | undefined;
  clock?: Clock | undefined;
  logger?: boolean | undefined;
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
        const decision = await options.provider.evaluate(body.action);
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
