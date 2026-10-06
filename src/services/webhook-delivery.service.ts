import { isValidObjectId, type Types } from "mongoose";
import { z } from "zod";
import { getEnv } from "../config/env.js";
import { decryptSecret } from "../crypto/envelope.js";
import { AppError } from "../errors/app-error.js";
import { bus } from "../events/bus.js";
import { logger } from "../logger/logger.js";
import { DeviceModel } from "../models/device.model.js";
import { EnvironmentModel } from "../models/environment.model.js";
import { ResourceModel } from "../models/resource.model.js";
import { UserModel } from "../models/user.model.js";
import { VariableModel } from "../models/variable.model.js";
import { WebhookDeliveryModel } from "../models/webhook-delivery.model.js";
import { WebhookEventModel } from "../models/webhook-event.model.js";
import { WebhookListenerModel } from "../models/webhook-listener.model.js";
import type { Pagination } from "../utils/response.js";
import { signWebhook, type WebhookProvider } from "../webhooks/signing.js";
import { assertRuntimeAccess, loadEnvironment, requireMembership } from "./access.service.js";
import { fakeApiKey, thinFakeResource } from "./fakes.service.js";
import type { RuntimeSubject } from "./runtime-access.service.js";
import { revalidate } from "./runtime-access.service.js";
import { claimObjects, ownersOf } from "./webhook-owner.service.js";

/** Undelivered events are kept this long (owner decision, PRD v1.28). */
export const WEBHOOK_RETENTION_MS = 24 * 3_600_000;
/** No ack within this time → pushed again (lost push, agent restarted mid-delivery). */
export const ACK_TIMEOUT_MS = 30_000;
/** After the app fails (refused, 5xx, timeout): 5 s, 15 s, 1 min, 5 min, 15 min, then every 30 min. */
const RETRY_MS = [5_000, 15_000, 60_000, 300_000, 900_000, 1_800_000];
/** Waiting on something outside the app (access paused, app not started): look again in 5 min (or on redeliver). */
const WAIT_MS = 300_000;
/** Unmatched events are re-routed this long after arrival (the owner write or a linking event may still come). */
const REROUTE_AFTER_MS = [2_000, 5_000, 15_000];
export const LISTENER_TTL_MS = 12 * 3_600_000;

const masterKey = () => Buffer.from(getEnv().MASTER_KEY, "base64");

/** Streams currently open on this instance, so the sweeper only pushes to devices that can receive. */
const openStreams = new Map<string, number>();
const streamKey = (deviceId: string, environmentId: string) => `${deviceId}:${environmentId}`;
export function streamOpened(deviceId: string, environmentId: string): () => void {
  const k = streamKey(deviceId, environmentId);
  openStreams.set(k, (openStreams.get(k) ?? 0) + 1);
  return () => {
    const n = (openStreams.get(k) ?? 1) - 1;
    if (n <= 0) openStreams.delete(k);
    else openStreams.set(k, n);
  };
}

function announce(d: { _id: Types.ObjectId; deviceId: Types.ObjectId; environmentId: Types.ObjectId }) {
  bus.publish({
    type: "webhook.deliver",
    deliveryId: d._id.toHexString(),
    deviceId: d.deviceId.toHexString(),
    environmentId: d.environmentId.toHexString(),
  });
}

/** Creates one delivery per device (idempotent per event+device) and pushes each to its stream. */
export async function enqueueDeliveries(
  event: { _id: Types.ObjectId; environmentId: Types.ObjectId; resourceId: Types.ObjectId; expiresAt: Date },
  devices: { deviceId: Types.ObjectId; userId: Types.ObjectId }[],
): Promise<number> {
  let created = 0;
  for (const dev of devices) {
    const res = await WebhookDeliveryModel.updateOne(
      { eventRef: event._id, deviceId: dev.deviceId },
      {
        $setOnInsert: {
          environmentId: event.environmentId,
          resourceId: event.resourceId,
          userId: dev.userId,
          status: "pending",
          // Pushed right below; the sweeper only re-pushes if no ack came back in time.
          nextAttemptAt: new Date(Date.now() + ACK_TIMEOUT_MS),
          expiresAt: event.expiresAt,
        },
      },
      { upsert: true },
    );
    if (res.upsertedId) {
      created += 1;
      announce({
        _id: res.upsertedId as Types.ObjectId,
        deviceId: dev.deviceId,
        environmentId: event.environmentId,
      });
    }
  }
  return created;
}

/**
 * Routes an event to the device(s) that made the object it describes; only when nobody owns that object do its direct
 * links decide (e.g. a charge → its PaymentIntent). A single owner also inherits the event's ids, so follow-ups route.
 */
export async function routeEvent(event: {
  _id: Types.ObjectId;
  environmentId: Types.ObjectId;
  resourceId: Types.ObjectId;
  provider: string;
  primaryIds?: string[];
  objectIds: string[];
  expiresAt: Date;
}): Promise<boolean> {
  const primary = event.primaryIds ?? [];
  let owners = await ownersOf(event.environmentId, event.provider, primary);
  if (owners.length === 0) owners = await ownersOf(event.environmentId, event.provider, event.objectIds);
  if (owners.length === 0) return false;
  const [only] = owners;
  if (owners.length === 1 && only)
    await claimObjects(
      { environmentId: event.environmentId, provider: event.provider as WebhookProvider, ...only },
      [...primary, ...event.objectIds],
    );
  await enqueueDeliveries(event, owners);
  await WebhookEventModel.updateOne({ _id: event._id }, { routing: "matched", nextRouteAt: null });
  return true;
}

export const nextRouteAt = (receivedAt: Date, attempts: number): Date | null => {
  const after = REROUTE_AFTER_MS[attempts];
  return after === undefined ? null : new Date(receivedAt.getTime() + after);
};

export interface WebhookPush {
  deliveryId: string;
  /** Bumped by every replay: the agent posts each generation once (its dedupe key is id + generation). */
  generation: number;
  eventId: string;
  provider: WebhookProvider;
  type: string;
  path: string;
  port: number | null;
  headers: Record<string, string>;
  body: string;
}

/**
 * Builds the SSE payload for one delivery to this device, re-signed with the device's fake (fresh timestamp each
 * attempt). Access is re-checked first (S3); anything that no longer applies is marked skipped and not sent.
 */
export async function renderPush(
  deliveryId: string,
  subject: RuntimeSubject,
): Promise<WebhookPush | undefined> {
  const delivery = await WebhookDeliveryModel.findOne({
    _id: deliveryId,
    deviceId: subject.deviceId,
    environmentId: subject.environmentId,
    status: "pending",
  }).lean();
  if (!delivery) return undefined;
  const skip = async (reason: string) => {
    await WebhookDeliveryModel.updateOne({ _id: delivery._id }, { status: "skipped", lastError: reason });
    return undefined;
  };
  const denied = await revalidate(subject);
  if (denied) {
    // Gone for good → skipped; anything that can come back (grant, kill switch, suspension) → keeps waiting.
    if (denied === "device revoked" || denied === "environment deleted") return skip(denied);
    await WebhookDeliveryModel.updateOne(
      { _id: delivery._id },
      { lastError: `waiting: ${denied}`, nextAttemptAt: new Date(Date.now() + WAIT_MS) },
    );
    return undefined;
  }
  const [event, resource] = await Promise.all([
    WebhookEventModel.findById(delivery.eventRef).select("+body").lean(),
    ResourceModel.findOne({ _id: delivery.resourceId, disabledAt: null }).lean(),
  ]);
  if (!event?.body) return skip("event expired");
  if (!resource) return skip("service removed or disabled");
  const config = (resource.config ?? {}) as {
    provider?: WebhookProvider;
    path?: string;
    thinPath?: string;
    port?: number;
    fakePrefix?: string;
  };
  const provider = config.provider ?? (event.provider as WebhookProvider);
  const body = Buffer.from(decryptSecret(masterKey(), event.body), "base64");
  // Thin events are signed with the thin key's fake when the app reads one; otherwise with the main key's.
  const thinKey =
    event.thin && (await VariableModel.exists({ resourceId: resource._id, field: "thinSecret" }));
  const fake = fakeApiKey(
    {
      deviceId: subject.deviceId,
      environmentId: subject.environmentId,
      resourceId: thinFakeResource(resource._id.toHexString(), Boolean(thinKey)),
    },
    config.fakePrefix ?? "",
  );
  const now = new Date();
  await WebhookDeliveryModel.updateOne(
    { _id: delivery._id },
    { lastPushedAt: now, nextAttemptAt: new Date(now.getTime() + ACK_TIMEOUT_MS) },
  );
  return {
    deliveryId: delivery._id.toHexString(),
    generation: delivery.generation ?? 0,
    eventId: event.eventId,
    provider,
    type: event.type,
    path: (event.thin && config.thinPath) || config.path || "/",
    port: config.port ?? null,
    headers: {
      "content-type": "application/json",
      ...(event.passHeaders as Record<string, string>),
      ...signWebhook(provider, fake, body),
    },
    body: body.toString("base64"),
  };
}

/** Pending deliveries of this device + environment, oldest first (sent when its stream opens). */
export async function pendingFor(subject: RuntimeSubject): Promise<string[]> {
  const rows = await WebhookDeliveryModel.find({
    deviceId: subject.deviceId,
    environmentId: subject.environmentId,
    status: "pending",
    expiresAt: { $gt: new Date() },
  })
    .sort({ createdAt: 1 })
    .limit(500)
    .select("_id")
    .lean();
  return rows.map((r) => r._id.toHexString());
}

/** The app just started under cb on this device: everything waiting for it goes out now (FR-WH-003). */
export async function redeliverPending(
  deviceId: string,
  environmentId: Types.ObjectId,
): Promise<{ queued: number }> {
  const rows = await WebhookDeliveryModel.find({
    deviceId,
    environmentId,
    status: "pending",
    expiresAt: { $gt: new Date() },
  })
    .sort({ createdAt: 1 })
    .limit(500)
    .select("_id deviceId environmentId")
    .lean();
  for (const d of rows) announce(d);
  return { queued: rows.length };
}

export const AckBody = z.object({
  ok: z.boolean(),
  status: z.number().int().min(0).max(999).optional(),
  error: z.string().max(300).optional(),
  ms: z.number().int().min(0).optional(),
  /** Which push this answers; an answer to an older generation (before a replay) changes nothing. */
  generation: z.number().int().min(0).optional(),
  /** No app is running under cb on that machine: not a failed attempt; delivery waits for the app to start. */
  noApp: z.boolean().optional(),
});

/** FR-WH-003: the agent reports what the app answered. Only the device the delivery belongs to may ack it. */
export async function ackDelivery(deviceId: string, deliveryId: string, input: z.infer<typeof AckBody>) {
  if (!isValidObjectId(deliveryId)) throw new AppError("NOT_FOUND", { message: "Delivery not found." });
  const delivery = await WebhookDeliveryModel.findOne({ _id: deliveryId, deviceId }).lean();
  if (!delivery) throw new AppError("NOT_FOUND", { message: "Delivery not found." });
  if (delivery.status !== "pending") return { status: delivery.status };
  if (input.generation !== undefined && input.generation !== (delivery.generation ?? 0))
    return { status: delivery.status };
  if (!input.ok && input.noApp) {
    await WebhookDeliveryModel.updateOne(
      { _id: delivery._id },
      { lastError: input.error ?? "app not running", nextAttemptAt: new Date(Date.now() + WAIT_MS) },
    );
    return { status: "pending" as const };
  }
  if (input.ok) {
    await WebhookDeliveryModel.updateOne(
      { _id: delivery._id },
      { status: "delivered", deliveredAt: new Date(), appStatus: input.status ?? null, lastError: null },
    );
    return { status: "delivered" as const };
  }
  const attempts = delivery.attempts + 1;
  const wait = RETRY_MS[Math.min(attempts - 1, RETRY_MS.length - 1)] ?? ACK_TIMEOUT_MS;
  await WebhookDeliveryModel.updateOne(
    { _id: delivery._id },
    {
      attempts,
      appStatus: input.status ?? null,
      lastError: input.error ?? (input.status ? `app answered ${input.status}` : "not delivered"),
      nextAttemptAt: new Date(Date.now() + wait),
    },
  );
  return { status: "pending" as const, retryInMs: wait };
}

/** Listener deliveries for an event nobody owns (devices that opted in). */
async function deliverToListeners(event: Parameters<typeof enqueueDeliveries>[0]): Promise<number> {
  const listeners = await WebhookListenerModel.find({
    environmentId: event.environmentId,
    expiresAt: { $gt: new Date() },
  })
    .select("deviceId userId")
    .lean();
  return enqueueDeliveries(event, listeners);
}

/**
 * Every few seconds: re-route unmatched events, hand late ones to listeners, re-push deliveries that are due on
 * streams open here, and expire what is older than 24 h (bodies are dropped at once; TTL removes the rows).
 */
export async function sweepWebhooks(now = new Date()): Promise<void> {
  const unmatched = await WebhookEventModel.find({
    routing: "unmatched",
    nextRouteAt: { $ne: null, $lte: now },
  })
    .limit(200)
    .lean();
  for (const event of unmatched) {
    if (await routeEvent(event)) continue;
    let attempts = event.routeAttempts;
    let next: Date | null;
    do {
      attempts += 1;
      next = nextRouteAt(event.receivedAt, attempts);
    } while (next && next <= now);
    await WebhookEventModel.updateOne({ _id: event._id }, { routeAttempts: attempts, nextRouteAt: next });
    if (!next) await deliverToListeners(event);
  }

  // Only devices with a stream open here can receive; offline ones get everything when they reconnect.
  const online = [...openStreams.keys()].slice(0, 1_000).map((k) => {
    const [deviceId, environmentId] = k.split(":");
    return { deviceId, environmentId };
  });
  if (online.length > 0) {
    const due = await WebhookDeliveryModel.find({
      status: "pending",
      nextAttemptAt: { $lte: now },
      expiresAt: { $gt: now },
      $or: online,
    })
      .sort({ nextAttemptAt: 1 })
      .limit(500)
      .select("_id deviceId environmentId")
      .lean();
    for (const d of due) announce(d);
  }

  await WebhookDeliveryModel.updateMany(
    { status: "pending", expiresAt: { $lte: now } },
    { status: "expired", lastError: "not delivered within 24 h" },
  );
  await WebhookEventModel.updateMany(
    { expiresAt: { $lte: now }, body: { $ne: null } },
    { $set: { body: null } },
  );
}

export const RedeliverBody = z.object({
  projectId: z.string().min(1),
  env: z.string().min(1),
  orgId: z.string().optional(),
});

export const ListenBody = z.object({
  projectId: z.string().min(1),
  env: z.string().min(1),
  orgId: z.string().optional(),
  unmatched: z.boolean(),
});

/** `cb webhooks listen`: this device also receives events nobody owns, for 12 h (or stops). */
export async function setListener(
  auth: { userId: string; deviceId: string },
  environmentId: Types.ObjectId,
  input: { unmatched: boolean },
) {
  const filter = { environmentId, deviceId: auth.deviceId };
  if (!input.unmatched) {
    await WebhookListenerModel.deleteOne(filter);
    return { listening: false, expiresAt: null };
  }
  const expiresAt = new Date(Date.now() + LISTENER_TTL_MS);
  await WebhookListenerModel.updateOne(
    filter,
    { $set: { userId: auth.userId, expiresAt } },
    { upsert: true },
  );
  return { listening: true, expiresAt: expiresAt.toISOString() };
}

export interface WebhookEventDto {
  id: string;
  eventId: string;
  type: string;
  provider: string;
  serviceId: string;
  serviceName: string;
  routing: "matched" | "unmatched";
  receivedAt: string;
  expiresAt: string;
  deliveries: {
    id: string;
    status: string;
    attempts: number;
    appStatus: number | null;
    lastError: string | null;
    deliveredAt: string | null;
    deviceName: string;
    userEmail: string;
  }[];
}

/** Dashboard: recent webhook events of an environment with per-device status — never bodies or secrets. */
export async function listWebhookEvents(
  actorId: string,
  envId: Types.ObjectId,
  page: { page: number; pageSize: number },
): Promise<{ items: WebhookEventDto[]; pagination: Pagination }> {
  await loadEnvironment(actorId, envId, "admin");
  const filter = { environmentId: envId };
  const [total, events] = await Promise.all([
    WebhookEventModel.countDocuments(filter),
    WebhookEventModel.find(filter)
      .sort({ receivedAt: -1 })
      .skip((page.page - 1) * page.pageSize)
      .limit(page.pageSize)
      .lean(),
  ]);
  const ids = events.map((e) => e._id);
  const [deliveries, resources] = await Promise.all([
    WebhookDeliveryModel.find({ eventRef: { $in: ids } }).lean(),
    ResourceModel.find({ _id: { $in: events.map((e) => e.resourceId) } })
      .select("name")
      .lean(),
  ]);
  const [devices, users] = await Promise.all([
    DeviceModel.find({ _id: { $in: deliveries.map((d) => d.deviceId) } })
      .select("name")
      .lean(),
    UserModel.find({ _id: { $in: deliveries.map((d) => d.userId) } })
      .select("email")
      .lean(),
  ]);
  const name = new Map(resources.map((r) => [r._id.toHexString(), r.name]));
  const device = new Map(devices.map((d) => [d._id.toHexString(), d.name]));
  const email = new Map(users.map((u) => [u._id.toHexString(), u.email]));
  const items = events.map((e) => ({
    id: e._id.toHexString(),
    eventId: e.eventId,
    type: e.type,
    provider: e.provider,
    serviceId: e.resourceId.toHexString(),
    serviceName: name.get(e.resourceId.toHexString()) ?? "",
    routing: e.routing as "matched" | "unmatched",
    receivedAt: e.receivedAt.toISOString(),
    expiresAt: e.expiresAt.toISOString(),
    deliveries: deliveries
      .filter((d) => d.eventRef.equals(e._id))
      .map((d) => ({
        id: d._id.toHexString(),
        status: d.status,
        attempts: d.attempts,
        appStatus: d.appStatus ?? null,
        lastError: d.lastError ?? null,
        deliveredAt: d.deliveredAt?.toISOString() ?? null,
        deviceName: device.get(d.deviceId.toHexString()) ?? "Removed device",
        userEmail: email.get(d.userId.toHexString()) ?? "",
      })),
  }));
  const totalPages = Math.max(1, Math.ceil(total / page.pageSize));
  return {
    items,
    pagination: {
      page: page.page,
      pageSize: page.pageSize,
      total,
      totalPages,
      hasNext: page.page < totalPages,
      hasPrev: page.page > 1,
    },
  };
}

/** Dashboard "Replay": queue the event again for its devices (or listeners when nobody owns it). */
export async function replayWebhookEvent(
  actorId: string,
  eventRef: Types.ObjectId,
): Promise<{ queued: number }> {
  const event = await WebhookEventModel.findById(eventRef).select("+body").lean();
  if (!event) throw new AppError("NOT_FOUND", { message: "Webhook event not found." });
  await requireMembership(actorId, event.orgId, "admin");
  if (!event.body || event.expiresAt <= new Date())
    throw new AppError("NOT_FOUND", {
      message: "This event is older than 24 hours and can no longer be replayed.",
    });
  const now = new Date();
  const existing = await WebhookDeliveryModel.find({ eventRef }).lean();
  if (existing.length === 0) return { queued: await deliverToListeners(event) };
  await WebhookDeliveryModel.updateMany(
    { eventRef, status: { $ne: "expired" } },
    { $set: { status: "pending", nextAttemptAt: now, lastError: null }, $inc: { generation: 1 } },
  );
  for (const d of existing) if (d.status !== "expired") announce(d);
  logger.info(`webhooks: event ${event.eventId} replayed to ${existing.length} device(s)`);
  return { queued: existing.filter((d) => d.status !== "expired").length };
}

/**
 * Dashboard "Send to me": an event nobody owns (a dashboard test event, `stripe trigger`) goes to the caller's own
 * signed-in machines; a delivery that already exists is sent once more. Never to anyone else.
 */
export async function sendWebhookToMe(
  actorId: string,
  eventRef: Types.ObjectId,
): Promise<{ queued: number }> {
  const event = await WebhookEventModel.findById(eventRef).select("+body").lean();
  if (!event) throw new AppError("NOT_FOUND", { message: "Webhook event not found." });
  await requireMembership(actorId, event.orgId, "admin");
  if (!event.body || event.expiresAt <= new Date())
    throw new AppError("NOT_FOUND", {
      message: "This event is older than 24 hours and can no longer be sent.",
    });
  const env = await EnvironmentModel.findById(event.environmentId).lean();
  if (!env) throw new AppError("NOT_FOUND", { message: "Environment not found." });
  // Only someone who may run this environment gets its events (grant, kill switch, suspension).
  await assertRuntimeAccess(actorId, env);
  const devices = await DeviceModel.find({ userId: actorId, revokedAt: null }).select("_id userId").lean();
  if (devices.length === 0)
    throw new AppError("VALIDATION_FAILED", {
      message: "Sign in on your machine with cb login and run your app with cb run, then send it again.",
    });
  // Every row of these devices, expired ones too (the unique index would make a new insert a no-op).
  const existing = await WebhookDeliveryModel.find({
    eventRef,
    deviceId: { $in: devices.map((d) => d._id) },
  }).lean();
  const has = new Set(existing.map((d) => d.deviceId.toHexString()));
  const fresh = devices
    .filter((d) => !has.has(d._id.toHexString()))
    .map((d) => ({ deviceId: d._id, userId: d.userId }));
  const created = await enqueueDeliveries(event, fresh);
  const again = existing;
  if (again.length > 0) {
    await WebhookDeliveryModel.updateMany(
      { _id: { $in: again.map((d) => d._id) } },
      {
        $set: { status: "pending", nextAttemptAt: new Date(), lastError: null, expiresAt: event.expiresAt },
        $inc: { generation: 1 },
      },
    );
    for (const d of again) announce(d);
  }
  if (created + again.length === 0)
    throw new AppError("VALIDATION_FAILED", {
      message: "No machine of yours could receive it. Sign in with cb login.",
    });
  return { queued: created + again.length };
}
