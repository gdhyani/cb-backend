import { createPrivateKey } from "node:crypto";
import http2 from "node:http2";
import type { Readable } from "node:stream";
import { signJwt, verifyJwt } from "../../crypto/jwt.js";
import { logger } from "../../logger/logger.js";
import { recordAudit } from "../../services/audit.service.js";
import { fakeApnsKey } from "../../services/fakes.service.js";
import type { TunnelContext } from "../types.js";
import {
  type GatewayRequest,
  type GatewayResponse,
  type Handler,
  HOP_BY_HOP,
  sendJson,
} from "./http-adapter.js";
import { upstreamCa } from "./upstream.js";

export interface ApnsConfig {
  keyId: string;
  teamId: string;
  /** Where requests are actually sent instead of the redirected Apple host (tests). */
  upstreamUrl?: string;
  redirectHosts?: string[];
}

// Apple rejects provider tokens older than 60 min; refresh well before that.
const REAL_TOKEN_TTL_MS = 50 * 60 * 1000;
const SESSION_IDLE_MS = 60_000;

/**
 * §10.8 apns: verify the app's provider JWT (ES256) with the device's fake .p8 public key, replace it with a
 * real JWT signed by the team's key (cached ≤ 50 min), and forward over HTTP/2 to Apple.
 */
export function createApnsHandler(ctx: TunnelContext): Handler {
  const config = ctx.resource.config as unknown as ApnsConfig;
  const realKey = createPrivateKey(ctx.secret);
  const fakePublic = fakeApnsKey({ deviceId: ctx.deviceId, resourceId: ctx.resource.id }).publicKey;
  let realToken: { jwt: string; at: number } | undefined;
  const sessions = new Map<string, http2.ClientHttp2Session>();

  const providerToken = () => {
    if (!realToken || Date.now() - realToken.at > REAL_TOKEN_TTL_MS) {
      const jwt = signJwt(
        "ES256",
        realKey,
        { iss: config.teamId, iat: Math.floor(Date.now() / 1000) },
        { kid: config.keyId },
      );
      realToken = { jwt, at: Date.now() };
    }
    return realToken.jwt;
  };

  const sessionFor = (origin: string) => {
    const existing = sessions.get(origin);
    if (existing && !existing.closed && !existing.destroyed) return existing;
    const ca = upstreamCa();
    const session = http2.connect(origin, ca ? { ca } : {});
    session.setTimeout(SESSION_IDLE_MS, () => session.close());
    session.on("error", () => sessions.delete(origin));
    session.on("close", () => sessions.delete(origin));
    sessions.set(origin, session);
    return session;
  };

  return (req: GatewayRequest, res: GatewayResponse) => {
    const token = /^bearer\s+(\S+)$/i.exec(String(req.headers.authorization ?? ""))?.[1] ?? "";
    const presented = verifyJwt(token, "ES256", fakePublic);
    if (!presented || presented.header.kid !== config.keyId || presented.payload.iss !== config.teamId) {
      req.resume();
      sendJson(res, 403, { reason: "InvalidProviderToken" });
      return;
    }
    const host = (ctx.host ?? "").toLowerCase();
    const origin = new URL(config.upstreamUrl ?? `https://${host}`).origin;
    const headers: http2.OutgoingHttpHeaders = {
      ":method": req.method ?? "POST",
      ":path": req.url ?? "/",
      authorization: `bearer ${providerToken()}`,
    };
    for (const [k, v] of Object.entries(req.headers)) {
      if (k.startsWith(":") || HOP_BY_HOP.has(k) || k === "authorization" || k === "host" || v === undefined)
        continue;
      headers[k] = v;
    }
    let upstream: http2.ClientHttp2Stream;
    try {
      upstream = sessionFor(origin).request(headers);
    } catch (err) {
      logger.warn(
        `apns ${ctx.resource.name}: cannot reach ${origin} — ${err instanceof Error ? err.message : String(err)}`,
      );
      sendJson(res, 502, { reason: "cb_upstream_unreachable" });
      return;
    }
    (req as unknown as Readable).pipe(upstream);
    upstream.on("response", (h) => {
      const status = Number(h[":status"] ?? 502);
      const out: Record<string, string | string[]> = {};
      for (const [k, v] of Object.entries(h))
        if (!k.startsWith(":") && !HOP_BY_HOP.has(k) && v !== undefined) out[k] = v as string;
      (res as import("node:http").ServerResponse).writeHead(status, out);
      upstream.pipe(res as unknown as NodeJS.WritableStream);
      void recordAudit({
        orgId: ctx.orgId,
        actorId: ctx.userId,
        deviceId: ctx.deviceId,
        projectId: ctx.projectId,
        environmentId: ctx.environmentId,
        resourceId: ctx.resource.id,
        action: "http.request",
        meta: {
          method: headers[":method"],
          host,
          path: (req.url ?? "/").split("?")[0],
          status,
          swap: "apns-jwt",
        },
      });
    });
    upstream.on("error", (err) => {
      logger.warn(`apns ${ctx.resource.name}: upstream ${origin} failed — ${err.message}`);
      sendJson(res, 502, { reason: "cb_upstream_unreachable" });
    });
  };
}
