import { randomBytes } from "node:crypto";
import type { Types } from "mongoose";
import { request } from "undici";
import { z } from "zod";
import { getEnv } from "../config/env.js";
import { encryptSecret } from "../crypto/envelope.js";
import { AppError } from "../errors/app-error.js";
import { upstreamDispatcher } from "../gateway/http/upstream.js";
import { logger } from "../logger/logger.js";
import { ResourceModel } from "../models/resource.model.js";
import { parseWebhookSecrets, serializeWebhookSecrets, type WebhookSecrets } from "../webhooks/secrets.js";
import { requireMembership } from "./access.service.js";
import { recordAudit } from "./audit.service.js";
import { touchEnvironment } from "./environment.service.js";
import { type ResourceDto, toResourceDto, webhookUrlOf } from "./resource.service.js";
import { readResourceSecret } from "./resource-secret.service.js";
import { withCaCert } from "./secret-file.service.js";

/**
 * FR-WH-001 Connect: with the provider's API key already stored in the same environment, cb creates (or points again)
 * the provider's webhook at this service's cb URL and keeps the signing secret — nobody copies a URL or a secret.
 * Stripe: full events (v1 endpoint, every event) and/or thin events (v2 event destination, a named event list).
 * Razorpay: one webhook (v1 webhooks API, works with a merchant key) with a secret cb makes.
 */

const STRIPE_API = "https://api.stripe.com";
const RAZORPAY_API = "https://api.razorpay.com";
/** Stripe's v2 API needs an explicit version. */
const STRIPE_V2_VERSION = "2026-09-30.endive";
/** Thin destinations cannot subscribe to every event (no "*"): the payment flows apps usually handle. */
export const STRIPE_THIN_EVENTS = [
  "v1.payment_intent.succeeded",
  "v1.payment_intent.payment_failed",
  "v1.payment_intent.canceled",
  "v1.charge.succeeded",
  "v1.charge.refunded",
  "v1.checkout.session.completed",
  "v1.checkout.session.expired",
  "v1.customer.subscription.created",
  "v1.customer.subscription.updated",
  "v1.customer.subscription.deleted",
  "v1.invoice.paid",
  "v1.invoice.payment_failed",
] as const;
/** What a Razorpay integration usually listens to; more can be ticked in the Razorpay Dashboard. */
export const RAZORPAY_EVENTS = [
  "payment.authorized",
  "payment.captured",
  "payment.failed",
  "order.paid",
  "refund.created",
  "refund.processed",
  "refund.failed",
] as const;

export const ConnectBody = z
  .object({
    /** Stripe only: which payloads the app's code reads — full (constructEvent), thin (parseEventNotification). */
    payloads: z
      .array(z.enum(["full", "thin"]))
      .min(1)
      .max(2)
      .optional(),
  })
  .strict();

const invalid = (message: string) => new AppError("VALIDATION_FAILED", { message });
const refused = (message: string, cause?: unknown) => new AppError("SERVICE_TEST_FAILED", { message, cause });

interface Api {
  base: string;
  caCert?: unknown;
}
interface Answer {
  status: number;
  json: unknown;
}

async function call(
  api: Api,
  method: "POST" | "PUT" | "DELETE",
  path: string,
  headers: Record<string, string>,
  body?: string,
): Promise<Answer> {
  try {
    const res = await request(new URL(path, api.base), {
      method,
      headers,
      body,
      dispatcher: upstreamDispatcher(api.caCert),
      headersTimeout: 15_000,
      bodyTimeout: 15_000,
    });
    return { status: res.statusCode, json: await res.body.json().catch(() => ({})) };
  } catch (err) {
    throw refused("The provider could not be reached to set up the webhook. Try again.", err);
  }
}

const ErrorBody = z.object({
  error: z
    .object({
      message: z.string().optional(),
      description: z.string().optional(),
      code: z.string().optional(),
    })
    .optional(),
});
const reasonOf = (a: Answer) => {
  const e = ErrorBody.safeParse(a.json);
  return (e.success && (e.data.error?.message ?? e.data.error?.description)) || `HTTP ${a.status}`;
};

/** The environment's API key service for a provider, with its real key (decrypted per use). */
async function providerKey(environmentId: Types.ObjectId, provider: "stripe" | "razorpay") {
  const key = await ResourceModel.findOne({
    environmentId,
    kind: "http",
    "config.provider": provider,
    disabledAt: null,
  })
    .sort({ createdAt: 1 })
    .lean();
  if (!key)
    throw invalid(
      provider === "stripe"
        ? "Add your Stripe secret key (type Stripe) in this environment first; cb uses it to create the webhook in Stripe."
        : "Add your Razorpay key (type Razorpay) in this environment first; cb uses it to create the webhook in Razorpay.",
    );
  // I3: a CA kept in the file store comes back into config (memory only) for the provider call.
  const config = ((await withCaCert(key)).config ?? {}) as {
    upstreamUrl?: string;
    caCert?: unknown;
    basicUser?: string;
  };
  return { secret: await readResourceSecret(key._id), config };
}

// ---------------------------------------------------------------- Stripe

const StripeEndpoint = z.object({
  id: z.string().regex(/^we_[A-Za-z0-9]+$/),
  secret: z.string().startsWith("whsec_").optional(),
  livemode: z.boolean().optional(),
});
const StripeDestination = z.object({
  id: z.string().regex(/^ed_[A-Za-z0-9_]+$/),
  livemode: z.boolean().optional(),
  webhook_endpoint: z.object({ signing_secret: z.string().startsWith("whsec_").nullish() }).optional(),
});

interface Connected {
  id: string;
  secret?: string;
  livemode?: boolean;
}

async function stripeFull(
  api: Api,
  key: string,
  url: string,
  existing: string | undefined,
  name: string,
): Promise<Connected> {
  const headers = { authorization: `Bearer ${key}`, "content-type": "application/x-www-form-urlencoded" };
  if (existing) {
    // Same endpoint, new address: Stripe keeps its signing secret.
    const a = await call(
      api,
      "POST",
      `/v1/webhook_endpoints/${encodeURIComponent(existing)}`,
      headers,
      new URLSearchParams({ url }).toString(),
    );
    const ok = StripeEndpoint.safeParse(a.json);
    if (a.status < 300 && ok.success) return { id: ok.data.id, livemode: ok.data.livemode };
    if (a.status !== 404) throw refused(`Stripe did not update the webhook: ${reasonOf(a)}.`);
  }
  const form = new URLSearchParams({ url, "enabled_events[]": "*", description: `cb: ${name}` });
  const a = await call(api, "POST", "/v1/webhook_endpoints", headers, form.toString());
  const ok = StripeEndpoint.safeParse(a.json);
  if (a.status >= 300 || !ok.success || !ok.data.secret)
    throw refused(
      `Stripe did not create the webhook: ${a.status < 300 ? "no signing secret in Stripe's answer" : reasonOf(a)}. A restricted key needs "Webhook Endpoints: Write"; or paste the signing secret yourself.`,
    );
  return { id: ok.data.id, secret: ok.data.secret, livemode: ok.data.livemode };
}

async function stripeThin(
  api: Api,
  key: string,
  url: string,
  existing: string | undefined,
  name: string,
): Promise<Connected> {
  const headers = {
    authorization: `Bearer ${key}`,
    "content-type": "application/json",
    "stripe-version": STRIPE_V2_VERSION,
  };
  if (existing) {
    const a = await call(
      api,
      "POST",
      `/v2/core/event_destinations/${encodeURIComponent(existing)}`,
      headers,
      JSON.stringify({ webhook_endpoint: { url } }),
    );
    const ok = StripeDestination.safeParse(a.json);
    if (a.status < 300 && ok.success) return { id: ok.data.id, livemode: ok.data.livemode };
    if (a.status !== 404) throw refused(`Stripe did not update the thin events destination: ${reasonOf(a)}.`);
  }
  const a = await call(
    api,
    "POST",
    "/v2/core/event_destinations",
    headers,
    JSON.stringify({
      name: `cb: ${name}`.slice(0, 100),
      type: "webhook_endpoint",
      event_payload: "thin",
      enabled_events: STRIPE_THIN_EVENTS,
      webhook_endpoint: { url },
      include: ["webhook_endpoint.signing_secret"],
    }),
  );
  const ok = StripeDestination.safeParse(a.json);
  const secret = ok.success ? ok.data.webhook_endpoint?.signing_secret : undefined;
  if (a.status >= 300 || !ok.success || !secret)
    throw refused(
      `Stripe did not create the thin events destination: ${a.status < 300 ? "no signing secret in Stripe's answer" : reasonOf(a)}.`,
    );
  return { id: ok.data.id, secret, livemode: ok.data.livemode };
}

async function stripeRemove(api: Api, key: string, full?: string, thin?: string) {
  if (full)
    await call(api, "DELETE", `/v1/webhook_endpoints/${encodeURIComponent(full)}`, {
      authorization: `Bearer ${key}`,
    });
  if (thin)
    await call(api, "DELETE", `/v2/core/event_destinations/${encodeURIComponent(thin)}`, {
      authorization: `Bearer ${key}`,
      "stripe-version": STRIPE_V2_VERSION,
    });
}

// ---------------------------------------------------------------- Razorpay

const RazorpayWebhook = z.object({
  id: z.string().regex(/^[A-Za-z0-9]{8,40}$/),
  active: z.boolean().optional(),
});
/** Razorpay's webhook API takes events as { name: "1" | "0" }. */
const razorpayEvents = (on: boolean) => Object.fromEntries(RAZORPAY_EVENTS.map((e) => [e, on ? "1" : "0"]));

async function razorpayConnect(
  api: Api,
  auth: string,
  url: string,
  secret: string,
  existing: string | undefined,
): Promise<Connected> {
  const headers = { authorization: auth, "content-type": "application/json" };
  if (existing) {
    // Razorpay's update replaces the URL and events; the stored secret stays valid.
    const a = await call(
      api,
      "PUT",
      `/v1/webhooks/${encodeURIComponent(existing)}`,
      headers,
      JSON.stringify({ url, events: razorpayEvents(true), active: true }),
    );
    const ok = RazorpayWebhook.safeParse(a.json);
    if (a.status < 300 && ok.success) return { id: ok.data.id };
    if (a.status !== 404) throw refused(`Razorpay did not update the webhook: ${reasonOf(a)}.`);
  }
  const a = await call(
    api,
    "POST",
    "/v1/webhooks",
    headers,
    JSON.stringify({ url, secret, events: razorpayEvents(true) }),
  );
  const ok = RazorpayWebhook.safeParse(a.json);
  if (a.status >= 300 || !ok.success)
    throw refused(
      `Razorpay did not create the webhook: ${a.status < 300 ? "unexpected answer" : reasonOf(a)}. You can add it in the Razorpay Dashboard with the URL and secret instead.`,
    );
  return { id: ok.data.id };
}

// ---------------------------------------------------------------- shared

async function loadWebhook(actorId: string, resourceId: Types.ObjectId) {
  const resource = await ResourceModel.findById(resourceId).lean();
  if (resource?.kind !== "webhook") throw new AppError("NOT_FOUND", { message: "Webhook not found." });
  await requireMembership(actorId, resource.orgId, "admin");
  return resource;
}

/** FR-WH-001: connect (or reconnect) the provider side of a webhook service. */
export async function connectWebhook(
  actorId: string,
  resourceId: Types.ObjectId,
  input: z.infer<typeof ConnectBody> = {},
): Promise<ResourceDto> {
  const resource = await loadWebhook(actorId, resourceId);
  const config = (resource.config ?? {}) as Record<string, unknown>;
  const provider = config.provider;
  if (provider !== "stripe" && provider !== "razorpay")
    throw invalid("This webhook's provider can't be connected.");
  if (provider === "razorpay" && input.payloads) throw invalid("Full and thin events are Stripe only.");
  const url = webhookUrlOf(resource._id.toHexString());
  if (!getEnv().PUBLIC_URL)
    throw invalid(
      `This cb server has no public address (PUBLIC_URL), so ${provider === "stripe" ? "Stripe" : "Razorpay"} could not reach it.`,
    );
  const { secret: key, config: keyConfig } = await providerKey(resource.environmentId, provider);
  const stored = parseWebhookSecrets(await readResourceSecret(resource._id));
  const secrets: WebhookSecrets = { ...stored };
  const next: Record<string, unknown> = { ...config, connectedUrl: url };

  if (provider === "stripe") {
    const api = { base: keyConfig.upstreamUrl || STRIPE_API, caCert: keyConfig.caCert };
    const was =
      (config.connectedPayloads as string[] | undefined) ?? (config.stripeEndpointId ? ["full"] : []);
    const want = input.payloads ?? (was.length > 0 ? was : ["full"]);
    let livemode: boolean | undefined;
    if (want.includes("full")) {
      const r = await stripeFull(api, key, url, config.stripeEndpointId as string | undefined, resource.name);
      next.stripeEndpointId = r.id;
      if (r.secret) secrets.snapshot = r.secret;
      livemode = r.livemode ?? livemode;
    }
    if (want.includes("thin")) {
      const r = await stripeThin(
        api,
        key,
        url,
        config.stripeThinDestinationId as string | undefined,
        resource.name,
      );
      next.stripeThinDestinationId = r.id;
      next.thinEvents = [...STRIPE_THIN_EVENTS];
      if (r.secret) secrets.thin = r.secret;
      livemode = r.livemode ?? livemode;
    }
    // A payload no longer wanted is removed in Stripe too, so nothing keeps sending to a route the app dropped.
    const dropFull = want.includes("full") ? undefined : (config.stripeEndpointId as string | undefined);
    const dropThin = want.includes("thin")
      ? undefined
      : (config.stripeThinDestinationId as string | undefined);
    if (dropFull || dropThin) {
      await stripeRemove(api, key, dropFull, dropThin).catch(() => undefined);
      if (dropFull) {
        delete next.stripeEndpointId;
        delete secrets.snapshot;
      }
      if (dropThin) {
        delete next.stripeThinDestinationId;
        delete next.thinEvents;
        delete secrets.thin;
      }
    }
    next.connectedPayloads = want;
    if (livemode !== undefined) next.livemode = livemode;
  } else {
    const api = { base: keyConfig.upstreamUrl || RAZORPAY_API, caCert: keyConfig.caCert };
    if (!keyConfig.basicUser)
      throw invalid("The Razorpay key in this environment has no Key ID; edit it and add one.");
    const auth = `Basic ${Buffer.from(`${keyConfig.basicUser}:${key}`).toString("base64")}`;
    // The stored secret is reused (cb-made or typed); a new one only when there is none.
    if (!secrets.snapshot) secrets.snapshot = randomBytes(32).toString("base64url");
    const r = await razorpayConnect(
      api,
      auth,
      url,
      secrets.snapshot,
      config.razorpayWebhookId as string | undefined,
    );
    next.razorpayWebhookId = r.id;
    next.razorpayEvents = [...RAZORPAY_EVENTS];
    next.livemode = keyConfig.basicUser.startsWith("rzp_live_");
  }

  next.secretsSet = { snapshot: Boolean(secrets.snapshot), thin: Boolean(secrets.thin) };
  next.secretOrigin = "connected";
  const update: Record<string, unknown> = {
    config: next,
    credentials: encryptSecret(Buffer.from(getEnv().MASTER_KEY, "base64"), serializeWebhookSecrets(secrets)),
  };
  if (secrets.snapshot !== stored.snapshot || secrets.thin !== stored.thin) update.rotatedAt = new Date();
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
  logger.info(`webhooks: ${resource.name} connected to ${provider}`);
  return toResourceDto(updated);
}

/**
 * When a connected webhook service is removed, its provider side goes too (Stripe: deleted; Razorpay: switched off —
 * its API has no delete). Best effort: a failure is logged and never blocks removing the key.
 */
export async function disconnectWebhook(resource: {
  environmentId: Types.ObjectId;
  name: string;
  config?: unknown;
}): Promise<void> {
  const config = (resource.config ?? {}) as Record<string, unknown>;
  try {
    if (config.provider === "stripe" && (config.stripeEndpointId || config.stripeThinDestinationId)) {
      const { secret, config: keyConfig } = await providerKey(resource.environmentId, "stripe");
      await stripeRemove(
        { base: keyConfig.upstreamUrl || STRIPE_API, caCert: keyConfig.caCert },
        secret,
        config.stripeEndpointId as string | undefined,
        config.stripeThinDestinationId as string | undefined,
      );
    }
    if (config.provider === "razorpay" && config.razorpayWebhookId) {
      const { secret, config: keyConfig } = await providerKey(resource.environmentId, "razorpay");
      const auth = `Basic ${Buffer.from(`${keyConfig.basicUser ?? ""}:${secret}`).toString("base64")}`;
      await call(
        { base: keyConfig.upstreamUrl || RAZORPAY_API, caCert: keyConfig.caCert },
        "PUT",
        `/v1/webhooks/${encodeURIComponent(String(config.razorpayWebhookId))}`,
        { authorization: auth, "content-type": "application/json" },
        JSON.stringify({ url: config.connectedUrl, events: razorpayEvents(false), active: false }),
      );
    }
  } catch (err) {
    logger.warn(
      `webhooks: could not remove the provider side of ${resource.name} — ${(err as Error).message}`,
    );
  }
}
