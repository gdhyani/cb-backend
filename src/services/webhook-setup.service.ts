import type { Types } from "mongoose";
import { request } from "undici";
import { z } from "zod";
import { getEnv } from "../config/env.js";
import { encryptSecret } from "../crypto/envelope.js";
import { AppError } from "../errors/app-error.js";
import { upstreamDispatcher } from "../gateway/http/upstream.js";
import { logger } from "../logger/logger.js";
import { ResourceModel } from "../models/resource.model.js";
import { parseWebhookSecrets, serializeWebhookSecrets } from "../webhooks/secrets.js";
import { requireMembership } from "./access.service.js";
import { recordAudit } from "./audit.service.js";
import { touchEnvironment } from "./environment.service.js";
import { type ResourceDto, toResourceDto, webhookUrlOf } from "./resource.service.js";
import { readResourceSecret } from "./resource-secret.service.js";

const STRIPE_API = "https://api.stripe.com";
const invalid = (message: string) => new AppError("VALIDATION_FAILED", { message });

/** What cb reads from Stripe's answer (zod at the boundary); anything else counts as a failure. */
const StripeBody = z.object({
  id: z
    .string()
    .regex(/^we_[A-Za-z0-9]+$/)
    .optional(),
  secret: z.string().startsWith("whsec_").optional(),
  error: z.object({ message: z.string().optional(), code: z.string().optional() }).optional(),
});
interface StripeAnswer {
  status: number;
  body: z.infer<typeof StripeBody>;
}

async function callStripe(
  api: { base: string; key: string; caCert?: unknown },
  path: string,
  form: URLSearchParams,
): Promise<StripeAnswer> {
  const res = await request(new URL(path, api.base), {
    method: "POST",
    headers: {
      authorization: `Bearer ${api.key}`,
      "content-type": "application/x-www-form-urlencoded",
    },
    body: form.toString(),
    dispatcher: upstreamDispatcher(api.caCert),
    headersTimeout: 15_000,
    bodyTimeout: 15_000,
  });
  const parsed = StripeBody.safeParse(await res.body.json().catch(() => ({})));
  return parsed.success ? { status: res.statusCode, body: parsed.data } : { status: 502, body: {} };
}

/**
 * FR-WH-001 Connect Stripe: with the Stripe secret key already stored in this environment, cb creates (or points
 * again) a webhook endpoint at this service's cb URL for every event and keeps the signing secret Stripe returns.
 * No URL or secret is copied by hand; the secret is never shown (L15).
 */
export async function connectStripeWebhook(
  actorId: string,
  resourceId: Types.ObjectId,
): Promise<ResourceDto> {
  const resource = await ResourceModel.findById(resourceId).lean();
  if (resource?.kind !== "webhook") throw new AppError("NOT_FOUND", { message: "Webhook not found." });
  await requireMembership(actorId, resource.orgId, "admin");
  const config = (resource.config ?? {}) as Record<string, unknown>;
  if (config.provider !== "stripe") throw invalid("Only Stripe webhooks can be connected automatically.");

  const stripeKey = await ResourceModel.findOne({
    environmentId: resource.environmentId,
    kind: "http",
    "config.provider": "stripe",
    disabledAt: null,
  })
    .sort({ createdAt: 1 })
    .lean();
  if (!stripeKey)
    throw invalid(
      "Add your Stripe secret key (type Stripe) in this environment first; cb uses it to create the webhook in Stripe.",
    );
  const url = webhookUrlOf(resource._id.toHexString());
  if (!getEnv().PUBLIC_URL)
    throw invalid("This cb server has no public address (PUBLIC_URL), so Stripe could not reach it.");
  const keyConfig = (stripeKey.config ?? {}) as { upstreamUrl?: string; caCert?: unknown };
  const api = {
    base: keyConfig.upstreamUrl || STRIPE_API,
    key: await readResourceSecret(stripeKey._id),
    caCert: keyConfig.caCert,
  };

  let endpointId = typeof config.stripeEndpointId === "string" ? config.stripeEndpointId : undefined;
  let newSecret: string | undefined;
  try {
    let answer: StripeAnswer | undefined;
    if (endpointId) {
      // Same endpoint, new address (e.g. the cb URL changed): Stripe keeps its signing secret.
      answer = await callStripe(
        api,
        `/v1/webhook_endpoints/${encodeURIComponent(endpointId)}`,
        new URLSearchParams({ url }),
      );
      if (answer.status === 404) {
        endpointId = undefined;
        answer = undefined;
      }
    }
    if (!answer) {
      const form = new URLSearchParams({
        url,
        "enabled_events[]": "*",
        description: `cb: ${resource.name}`,
        "metadata[cb_service]": resource._id.toHexString(),
      });
      answer = await callStripe(api, "/v1/webhook_endpoints", form);
      if (answer.status < 300 && answer.body.id && answer.body.secret) {
        endpointId = answer.body.id;
        newSecret = answer.body.secret;
      } else if (answer.status < 300)
        answer = { status: 502, body: { error: { message: "no signing secret in Stripe's answer" } } };
    }
    if (answer.status >= 300 || !endpointId || (!newSecret && !config.stripeEndpointId)) {
      const reason = answer.body.error?.message ?? `HTTP ${answer.status}`;
      throw new AppError("SERVICE_TEST_FAILED", {
        message: `Stripe did not create the webhook: ${reason}. A restricted key needs "Webhook Endpoints: Write"; or paste the signing secret yourself.`,
      });
    }
  } catch (err) {
    if (err instanceof AppError) throw err;
    throw new AppError("SERVICE_TEST_FAILED", {
      message: "Stripe could not be reached to create the webhook. Try again.",
      cause: err,
    });
  }

  const stored = parseWebhookSecrets(await readResourceSecret(resource._id));
  const secrets = { ...stored, ...(newSecret ? { snapshot: newSecret } : {}) };
  const nextConfig = {
    ...config,
    stripeEndpointId: endpointId,
    connectedUrl: url,
    secretsSet: { snapshot: Boolean(secrets.snapshot), thin: Boolean(secrets.thin) },
    ...(newSecret ? { secretOrigin: "connected" } : {}),
  };
  const update: Record<string, unknown> = { config: nextConfig };
  if (newSecret)
    Object.assign(update, {
      credentials: encryptSecret(
        Buffer.from(getEnv().MASTER_KEY, "base64"),
        serializeWebhookSecrets(secrets),
      ),
      rotatedAt: new Date(),
    });
  const updated = await ResourceModel.findByIdAndUpdate(resource._id, update, {
    returnDocument: "after",
  }).lean();
  if (!updated) throw new AppError("NOT_FOUND", { message: "Webhook not found." });
  await touchEnvironment(resource.environmentId);
  await recordAudit({
    orgId: resource.orgId,
    actorId,
    projectId: resource.projectId,
    environmentId: resource.environmentId,
    resourceId: resource._id,
    action: "resource.webhook_connected",
    target: resource.name,
  });
  logger.info(`webhooks: ${resource.name} connected to Stripe endpoint ${endpointId}`);
  return toResourceDto(updated);
}
