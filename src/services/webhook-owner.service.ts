import { Types } from "mongoose";
import { logger } from "../logger/logger.js";
import { WebhookOwnerModel } from "../models/webhook-owner.model.js";
import { idsFromPath, idsFromResponse } from "../webhooks/routing.js";
import { WEBHOOK_PROVIDERS, type WebhookProvider } from "../webhooks/signing.js";

/** Routing memory outlives event retention: subscriptions and refunds arrive weeks after the object was made. */
export const OWNER_TTL_MS = 30 * 24 * 3_600_000;

export interface OwnerScope {
  environmentId: string | Types.ObjectId;
  deviceId: string | Types.ObjectId;
  userId: string | Types.ObjectId;
  provider: WebhookProvider;
}

export const isWebhookProvider = (p: unknown): p is WebhookProvider =>
  typeof p === "string" && (WEBHOOK_PROVIDERS as readonly string[]).includes(p);

const PROVIDER_HOSTS: Record<string, WebhookProvider> = {
  "api.stripe.com": "stripe",
  "api.razorpay.com": "razorpay",
};

/** The payment provider an http service talks to: its preset, else the real API host (services made without one). */
export function paymentProviderOf(config: {
  provider?: unknown;
  upstreamUrl?: unknown;
}): WebhookProvider | undefined {
  if (isWebhookProvider(config.provider)) return config.provider;
  try {
    return PROVIDER_HOSTS[new URL(String(config.upstreamUrl)).hostname];
  } catch {
    return undefined;
  }
}

/** Records that this device made these objects; the first device keeps them (FR-WH-002). */
export async function claimObjects(scope: OwnerScope, objectIds: string[]): Promise<void> {
  if (objectIds.length === 0) return;
  const expiresAt = new Date(Date.now() + OWNER_TTL_MS);
  const oid = (v: string | Types.ObjectId) => new Types.ObjectId(String(v));
  const environmentId = oid(scope.environmentId);
  const owner = { deviceId: oid(scope.deviceId), userId: oid(scope.userId) };
  await WebhookOwnerModel.bulkWrite(
    objectIds.map((objectId) => ({
      updateOne: {
        filter: { environmentId, provider: scope.provider, objectId },
        update: { $setOnInsert: { ...owner, expiresAt } },
        upsert: true,
      },
    })),
    { ordered: false },
  );
  // Only the owner keeps its claims alive; another device touching the object never extends them.
  await WebhookOwnerModel.updateMany(
    { environmentId, provider: scope.provider, objectId: { $in: objectIds }, deviceId: owner.deviceId },
    { $set: { expiresAt } },
  );
}

/** HTTP gateway hook: learn ownership from a successful POST (request path + JSON response). Never throws. */
export function learnFromResponse(scope: OwnerScope, path: string, status: number, body: Buffer): void {
  if (status < 200 || status >= 300) return;
  let json: unknown;
  try {
    json = JSON.parse(body.toString("utf8"));
  } catch {
    json = undefined;
  }
  const ids = [...new Set([...idsFromPath(path), ...(json === undefined ? [] : idsFromResponse(json))])];
  claimObjects(scope, ids).catch((err: unknown) =>
    logger.warn(
      `webhooks: could not record object owners — ${err instanceof Error ? err.message : String(err)}`,
    ),
  );
}

/** Devices that made any of these objects, with the user of each. */
export async function ownersOf(
  environmentId: Types.ObjectId,
  provider: string,
  objectIds: string[],
): Promise<{ deviceId: Types.ObjectId; userId: Types.ObjectId }[]> {
  if (objectIds.length === 0) return [];
  const rows = await WebhookOwnerModel.find({ environmentId, provider, objectId: { $in: objectIds } })
    .select("deviceId userId")
    .lean();
  const byDevice = new Map(rows.map((r) => [r.deviceId.toHexString(), r] as const));
  return [...byDevice.values()].map((r) => ({ deviceId: r.deviceId, userId: r.userId }));
}
