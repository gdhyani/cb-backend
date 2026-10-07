import { Transform } from "node:stream";
import type { Types } from "mongoose";
import { logger } from "../logger/logger.js";
import { type ResourceKind, ResourceModel } from "../models/resource.model.js";

/**
 * B11 key health: whether the provider still accepts the stored key. Shown to admins as a status dot (green ok, red
 * "Expired" for rejected); the key itself stays hidden in every state. Reasons are cb's own words — never the
 * provider's response, which can quote part of a key.
 */
export type HealthStatus = "ok" | "rejected" | "unknown";
export interface Health {
  status: HealthStatus;
  reason?: string;
}

const REPLACE = "The key may have been deleted, rotated or expired at the provider. Replace value to fix it.";

const AWS_REJECTED =
  /InvalidAccessKeyId|SignatureDoesNotMatch|UnrecognizedClientException|InvalidClientTokenId/;
const KEY_INVALID_400 = /API_KEY_INVALID|API key not valid/i;

/** An upstream HTTP answer to a request that carried the real key. Undefined = says nothing about the key. */
export function healthFromHttp(kind: ResourceKind, status: number, bodyHead: string): Health | undefined {
  if (status >= 200 && status < 300) return { status: "ok" };
  if (status === 401)
    return { status: "rejected", reason: `The provider answered 401 Unauthorized. ${REPLACE}` };
  if (kind === "aws" && status === 403 && AWS_REJECTED.test(bodyHead))
    return {
      status: "rejected",
      reason: `AWS does not recognise the access key or its signature. ${REPLACE}`,
    };
  if (status === 400 && KEY_INVALID_400.test(bodyHead))
    return { status: "rejected", reason: `The provider says the API key is not valid. ${REPLACE}` };
  return undefined;
}

const DB_REJECTED = /rejected the stored credentials|authentication failed|smtp upstream rejected "AUTH/i;

/** A gateway upstream failure (stream adapters). Undefined = not a credential problem (network, TLS, protocol). */
export function healthFromUpstreamError(message: string): Health | undefined {
  return DB_REJECTED.test(message)
    ? { status: "rejected", reason: `The server refused the stored login. ${REPLACE}` }
    : undefined;
}

/** One write per resource per 30 s while the status holds; a change of status is written at once. */
const THROTTLE_MS = 30_000;
/** Hard cap on remembered resources, on top of dropping entries whose window has passed (M1). */
const THROTTLE_MAX = 5_000;
/** Insertion order = last write order, so the oldest entries are always at the front. */
const last = new Map<string, { status: HealthStatus; at: number }>();

function remember(key: string, status: HealthStatus, now: number): void {
  last.delete(key);
  last.set(key, { status, at: now });
  for (const [k, v] of last) {
    if (last.size <= THROTTLE_MAX && now - v.at < THROTTLE_MS) break;
    last.delete(k);
  }
}

/**
 * Records a key's health. `keyVersion` is the resource's `rotatedAt` when the reporter read the key: a report about
 * a key that was replaced since (an old tunnel, a slow test) matches nothing and is dropped (M1). Undefined = the
 * caller just wrote the key itself and needs no check.
 */
export async function markHealth(
  resourceId: Types.ObjectId | string,
  health: Health | undefined,
  keyVersion?: Date | string | null,
): Promise<void> {
  if (!health) return;
  const id = String(resourceId);
  const version = keyVersion == null ? keyVersion : new Date(keyVersion);
  const key = `${id}@${version === undefined ? "*" : (version?.getTime() ?? "none")}`;
  const now = Date.now();
  const prev = last.get(key);
  if (prev && prev.status === health.status && now - prev.at < THROTTLE_MS) return;
  remember(key, health.status, now);
  await ResourceModel.updateOne(version === undefined ? { _id: id } : { _id: id, rotatedAt: version }, {
    $set: { health: { status: health.status, reason: health.reason ?? null, checkedAt: new Date() } },
  }).catch((err: unknown) =>
    logger.warn(`key health: could not record for ${id} — ${err instanceof Error ? err.message : "error"}`),
  );
}

/** Fire-and-forget form for the data plane: never delays or breaks a request. */
export function noteHealth(
  resourceId: Types.ObjectId | string,
  health: Health | undefined,
  keyVersion?: Date | string | null,
): void {
  void markHealth(resourceId, health, keyVersion);
}

/** Tests: forget throttling state. */
export function resetHealthThrottle(): void {
  last.clear();
}

/** Tests: how many throttle entries are remembered. */
export function healthThrottleSize(): number {
  return last.size;
}

const TEST_REJECTED =
  /rejected the key|HTTP 401|InvalidAccessKeyId|SignatureDoesNotMatch|UnrecognizedClientException|password authentication failed|Access denied for user|WRONGPASS|invalid username-password|Authentication failed|invalid_grant|invalid_client|API_KEY_INVALID|\b535\b/i;

/** Save & test / Test connection outcome → health. A network or TLS failure says nothing about the key. */
export function healthFromTest(result: { ok: boolean; message: string }): Health | undefined {
  if (result.ok) return { status: "ok" };
  return TEST_REJECTED.test(result.message)
    ? { status: "rejected", reason: `Test connection: the provider refused the key. ${REPLACE}` }
    : undefined;
}

/**
 * Data plane: classifies an upstream answer without delaying it. 2xx/401 are decided from the status; a 400/403 is
 * decided from the first 2 KB of the body (passed through untouched).
 */
export function healthTap(
  kind: ResourceKind,
  status: number,
  resourceId: string,
  keyVersion: string | null | undefined,
): Transform | undefined {
  if (status !== 400 && status !== 403) {
    noteHealth(resourceId, healthFromHttp(kind, status, ""), keyVersion);
    return undefined;
  }
  let head = "";
  return new Transform({
    transform(chunk: Buffer, _enc, cb) {
      if (head.length < 2048) head += chunk.toString("utf8", 0, Math.min(chunk.length, 2048 - head.length));
      cb(null, chunk);
    },
    flush(cb) {
      noteHealth(resourceId, healthFromHttp(kind, status, head), keyVersion);
      cb();
    },
  });
}
