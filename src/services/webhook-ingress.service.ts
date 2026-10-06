import { createHash } from "node:crypto";
import { isValidObjectId } from "mongoose";
import { getEnv } from "../config/env.js";
import { encryptSecret } from "../crypto/envelope.js";
import { AppError } from "../errors/app-error.js";
import { logger } from "../logger/logger.js";
import { ResourceModel } from "../models/resource.model.js";
import { WebhookEventModel } from "../models/webhook-event.model.js";
import { eventTargets, idsFromEvent } from "../webhooks/routing.js";
import { isThinEvent, parseWebhookSecrets, secretsToTry } from "../webhooks/secrets.js";
import { eventIdOf, type HeaderMap, verifyWebhook, type WebhookProvider } from "../webhooks/signing.js";
import { readResourceSecret } from "./resource-secret.service.js";
import { nextRouteAt, routeEvent, WEBHOOK_RETENTION_MS } from "./webhook-delivery.service.js";
import { isWebhookProvider } from "./webhook-owner.service.js";

/**
 * Flood guards, per second: verified calls per service (providers send far fewer), and failed signatures per caller
 * IP — so someone holding only the URL cannot push the real provider into 429s.
 */
const MAX_VERIFIED_PER_SECOND = 60;
const MAX_FAILED_PER_IP_SECOND = 20;
type Windows = Map<string, { second: number; count: number }>;
const verified: Windows = new Map();
const failed: Windows = new Map();
function allow(windows: Windows, key: string, max: number): boolean {
  const second = Math.floor(Date.now() / 1000);
  const w = windows.get(key);
  if (!w || w.second !== second) {
    if (windows.size > 10_000) for (const [k, v] of windows) if (v.second < second) windows.delete(k);
    windows.set(key, { second, count: 1 });
    return true;
  }
  w.count += 1;
  return w.count <= max;
}
const overLimit = (windows: Windows, key: string, max: number) => {
  const w = windows.get(key);
  return Boolean(w && w.second === Math.floor(Date.now() / 1000) && w.count >= max);
};

/** Main object(s) first; unknown payload shapes fall back to every id they mention. */
function targetsOf(json: Record<string, unknown>): { primaryIds: string[]; objectIds: string[] } {
  const t = eventTargets(json);
  return t.primary.length > 0
    ? { primaryIds: t.primary, objectIds: t.linked }
    : { primaryIds: [], objectIds: idsFromEvent(json) };
}

const notFound = () => new AppError("NOT_FOUND", { message: "Webhook endpoint not found." });

/**
 * FR-WH-001 central ingress: the provider is the caller and the signature is the only trust. Verifies with the
 * real signing secret, stores the event once (provider retries are duplicates), routes it and answers at once —
 * the provider never waits for a laptop.
 */
export async function ingestWebhook(
  serviceId: string,
  body: Buffer,
  headers: HeaderMap,
  callerIp = "",
): Promise<{ accepted: true; duplicate: boolean }> {
  if (!isValidObjectId(serviceId)) throw notFound();
  const tooMany = () => new AppError("RATE_LIMITED", { message: "Too many webhook calls." });
  if (overLimit(failed, callerIp, MAX_FAILED_PER_IP_SECOND)) throw tooMany();
  const service = await ResourceModel.findOne({ _id: serviceId, kind: "webhook", disabledAt: null }).lean();
  const config = (service?.config ?? {}) as { provider?: unknown };
  if (!service || !isWebhookProvider(config.provider)) throw notFound();
  const provider: WebhookProvider = config.provider;
  let json: Record<string, unknown> = {};
  try {
    const parsed = JSON.parse(body.toString("utf8")) as unknown;
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed))
      json = parsed as Record<string, unknown>;
  } catch {
    // Signed but not JSON: delivered as-is, just never routed by object id.
  }
  // One cb URL serves Stripe's snapshot and thin destinations; each signs with its own secret.
  const thin = provider === "stripe" && isThinEvent(json);
  const secrets = secretsToTry(parseWebhookSecrets(await readResourceSecret(service._id)), thin);
  if (!secrets.some((secret) => verifyWebhook(provider, secret, body, headers))) {
    allow(failed, callerIp, MAX_FAILED_PER_IP_SECOND);
    throw new AppError("WEBHOOK_SIGNATURE_INVALID", {
      message: "Signature does not match this endpoint's signing secret.",
    });
  }
  if (!allow(verified, serviceId, MAX_VERIFIED_PER_SECOND)) throw tooMany();
  const eventId = eventIdOf(provider, body, headers);
  const type = String((provider === "stripe" ? json.type : json.event) ?? "");
  const receivedAt = new Date();
  const event = new WebhookEventModel({
    orgId: service.orgId,
    environmentId: service.environmentId,
    resourceId: service._id,
    provider,
    eventId,
    type: type.slice(0, 120),
    thin,
    passHeaders: headers["x-razorpay-event-id"]
      ? { "x-razorpay-event-id": headers["x-razorpay-event-id"] }
      : {},
    body: encryptSecret(Buffer.from(getEnv().MASTER_KEY, "base64"), body.toString("base64")),
    ...targetsOf(json),
    bodyHash: createHash("sha256").update(body).digest("hex"),
    routing: "unmatched",
    nextRouteAt: nextRouteAt(receivedAt, 0),
    receivedAt,
    expiresAt: new Date(receivedAt.getTime() + WEBHOOK_RETENTION_MS),
  });
  try {
    await event.save();
  } catch (err) {
    if ((err as { code?: number }).code === 11000) return { accepted: true, duplicate: true };
    throw err;
  }
  const matched = await routeEvent(event.toObject());
  logger.info(`webhook ${provider} ${type || "event"} ${eventId} → ${matched ? "routed" : "unmatched"}`);
  return { accepted: true, duplicate: false };
}
