import type { NextFunction, Request, Response } from "express";
import { hashToken } from "../crypto/tokens.js";
import { AppError } from "../errors/app-error.js";
import { toAppError } from "../errors/to-app-error.js";
import { getContext, runWithContext } from "../logger/context.js";
import { DeviceModel } from "../models/device.model.js";
import { UserModel } from "../models/user.model.js";
import { WebSessionModel } from "../models/web-session.model.js";

export const SESSION_COOKIE = "cb_session";
export const CSRF_HEADER = "x-cb-csrf";
export const DEVICE_TOKEN_PREFIX = "cbd_";
const DEVICE_TTL_MS = 30 * 86_400_000;
const TOUCH_INTERVAL_MS = 60_000;
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

export interface AuthContext {
  userId: string;
  kind: "web" | "device";
  sessionId?: string;
  deviceId?: string;
}

/** Resolves a device bearer token to its user (also used by the tunnel and SSE). */
export async function resolveDeviceToken(token: string): Promise<AuthContext | undefined> {
  if (!token.startsWith(DEVICE_TOKEN_PREFIX)) return undefined;
  const now = new Date();
  const device = await DeviceModel.findOne({
    tokenHash: hashToken(token),
    revokedAt: null,
    expiresAt: { $gt: now },
  });
  if (!device) return undefined;
  const user = await UserModel.findOne({ _id: device.userId, disabledAt: null }).select("_id").lean();
  if (!user) return undefined;
  if (!device.lastSeenAt || now.getTime() - device.lastSeenAt.getTime() > TOUCH_INTERVAL_MS) {
    // Rolling expiry: active devices stay logged in.
    await DeviceModel.updateOne(
      { _id: device._id },
      { lastSeenAt: now, expiresAt: new Date(now.getTime() + DEVICE_TTL_MS) },
    );
  }
  return { userId: device.userId.toHexString(), kind: "device", deviceId: device._id.toHexString() };
}

async function resolveWebSession(token: string): Promise<AuthContext | undefined> {
  const now = new Date();
  const session = await WebSessionModel.findOne({
    tokenHash: hashToken(token),
    revokedAt: null,
    expiresAt: { $gt: now },
  }).lean();
  if (!session) return undefined;
  if (!session.lastSeenAt || now.getTime() - session.lastSeenAt.getTime() > TOUCH_INTERVAL_MS)
    await WebSessionModel.updateOne({ _id: session._id }, { lastSeenAt: now });
  const user = await UserModel.findOne({ _id: session.userId, disabledAt: null }).select("_id").lean();
  if (!user) return undefined;
  return { userId: session.userId.toHexString(), kind: "web", sessionId: session._id.toHexString() };
}

export function bearerToken(req: Request): string | undefined {
  const header = req.header("authorization");
  return header?.startsWith("Bearer ") ? header.slice("Bearer ".length).trim() : undefined;
}

/** Runs on every request: attaches res.locals.auth when a valid cookie or device token is present. */
export async function authenticateMiddleware(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const bearer = bearerToken(req);
    const cookie = (req.cookies as Record<string, string> | undefined)?.[SESSION_COOKIE];
    const auth = bearer
      ? await resolveDeviceToken(bearer)
      : cookie
        ? await resolveWebSession(cookie)
        : undefined;
    if (!auth) {
      next();
      return;
    }
    res.locals.auth = auth;
    const ctx = getContext();
    runWithContext(
      { correlationId: ctx?.correlationId ?? String(res.locals.correlationId), userId: auth.userId },
      next,
    );
  } catch (err) {
    next(toAppError(err, "auth.middleware.authenticate: failed to resolve credentials"));
  }
}

/** Route guard: requires a user; cookie-authenticated mutations also need the CSRF header (M0-D4). */
export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  const auth = res.locals.auth;
  if (!auth) {
    next(
      new AppError("UNAUTHORIZED", {
        context: `auth: ${req.method} ${req.originalUrl} without valid credentials`,
      }),
    );
    return;
  }
  if (auth.kind === "web" && !SAFE_METHODS.has(req.method) && req.header(CSRF_HEADER) !== "1") {
    next(
      new AppError("CSRF_REQUIRED", {
        context: `auth: ${req.method} ${req.originalUrl} without ${CSRF_HEADER}`,
      }),
    );
    return;
  }
  next();
}

/**
 * For routes that work signed out but also use a session when present (accept-invite): a cookie-authenticated
 * mutation still needs the CSRF header (FR-AUTH-001, M0-D4).
 */
export function csrfIfSession(req: Request, res: Response, next: NextFunction): void {
  const auth = res.locals.auth;
  if (auth?.kind === "web" && !SAFE_METHODS.has(req.method) && req.header(CSRF_HEADER) !== "1") {
    next(
      new AppError("CSRF_REQUIRED", {
        context: `auth: ${req.method} ${req.originalUrl} without ${CSRF_HEADER}`,
      }),
    );
    return;
  }
  next();
}

/** Narrow helper for controllers that sit behind requireAuth. */
export function authOf(res: Response): AuthContext {
  const auth = res.locals.auth;
  if (!auth) throw new AppError("UNAUTHORIZED");
  return auth;
}
