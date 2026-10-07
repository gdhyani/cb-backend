import { createHash, randomBytes } from "node:crypto";
import type { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { request } from "undici";
import { getEnv } from "../../config/env.js";
import { decryptSecret, encryptSecret } from "../../crypto/envelope.js";
import { signJwt, verifyJwt } from "../../crypto/jwt.js";
import { logger } from "../../logger/logger.js";
import { TokenSwapModel } from "../../models/token-swap.model.js";
import { recordAudit } from "../../services/audit.service.js";
import { fakeGooglePublicKey } from "../../services/fakes.service.js";
import type { TunnelContext } from "../types.js";
import {
  type GatewayRequest,
  type GatewayResponse,
  type Handler,
  HOP_BY_HOP,
  sendJson,
} from "./http-adapter.js";
import { readBody } from "./oauth-adapter.js";
import { createRedactor, decoded, redactHeaders } from "./redaction.js";
import { upstreamDispatcher } from "./upstream.js";

export interface GoogleSaConfig {
  projectId: string;
  clientEmail: string;
  tokenUri: string;
  /** Where requests are actually sent instead of the redirected Google host (private endpoints, tests). */
  upstreamUrl?: string;
  redirectHosts?: string[];
}

interface ServiceAccountKey {
  client_email: string;
  private_key: string;
  private_key_id?: string;
  token_uri?: string;
}

const JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer";
export const FAKE_GOOGLE_TOKEN_PREFIX = "ya29.cb_";
const masterKey = () => Buffer.from(getEnv().MASTER_KEY, "base64");
const hashToken = (token: string) => createHash("sha256").update(token).digest("hex");

const unauthenticated = (res: GatewayResponse, message: string) =>
  sendJson(res, 401, { error: { code: 401, status: "UNAUTHENTICATED", message: `cb: ${message}` } });

/**
 * §10.8 google-sa (Firebase Admin / FCM). Token endpoint: verify the device's assertion with its fake public key,
 * sign a real assertion with the real service-account key, exchange it, and hand back a fake access token.
 * Every other request on a redirected Google host: swap that fake bearer for the real one.
 */
export function createGoogleSaHandler(ctx: TunnelContext): Handler {
  const config = ctx.resource.config as unknown as GoogleSaConfig;
  const real = JSON.parse(ctx.secret) as ServiceAccountKey;
  const tokenUrl = new URL(config.tokenUri);
  const scope = { deviceId: ctx.deviceId, resourceId: ctx.resource.id };
  const upstreamFor = (host: string) => new URL(config.upstreamUrl ?? `https://${host}`);
  const audit = (meta: Record<string, unknown>) =>
    void recordAudit({
      orgId: ctx.orgId,
      actorId: ctx.userId,
      deviceId: ctx.deviceId,
      projectId: ctx.projectId,
      environmentId: ctx.environmentId,
      resourceId: ctx.resource.id,
      action: "http.request",
      meta,
    });

  async function exchangeToken(req: GatewayRequest, res: GatewayResponse, host: string): Promise<void> {
    const form = new URLSearchParams((await readBody(req)).toString("utf8"));
    if (form.get("grant_type") !== JWT_BEARER)
      return sendJson(res, 400, {
        error: "unsupported_grant_type",
        error_description: "cb: only service-account (jwt-bearer) grants are brokered for this resource",
      });
    const publicPem = await fakeGooglePublicKey(scope);
    const presented = publicPem ? verifyJwt(form.get("assertion") ?? "", "RS256", publicPem) : null;
    const now = Math.floor(Date.now() / 1000);
    if (!presented || Number(presented.payload.exp ?? 0) < now)
      return sendJson(res, 400, {
        error: "invalid_grant",
        error_description: "cb: assertion is not signed by this device's key",
      });

    // Same scope / subject / audience the SDK asked for, signed by the real key.
    const { scope: wanted, sub, target_audience } = presented.payload;
    const assertion = signJwt(
      "RS256",
      real.private_key,
      {
        iss: real.client_email,
        aud: real.token_uri ?? config.tokenUri,
        iat: now,
        exp: now + 3600,
        ...(wanted ? { scope: wanted } : {}),
        ...(sub ? { sub } : {}),
        ...(target_audience ? { target_audience } : {}),
      },
      real.private_key_id ? { kid: real.private_key_id } : {},
    );
    const upstream = upstreamFor(host);
    const body = new URLSearchParams({ grant_type: JWT_BEARER, assertion }).toString();
    const up = await request(new URL(tokenUrl.pathname, upstream.origin), {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", host: upstream.host },
      body,
      dispatcher: upstreamDispatcher(),
    });
    const text = await up.body.text();
    let json: Record<string, unknown> = {};
    try {
      json = JSON.parse(text) as Record<string, unknown>;
    } catch {
      json = { error: "upstream_error" };
    }
    const accessToken = typeof json.access_token === "string" ? json.access_token : undefined;
    if (up.statusCode !== 200 || !accessToken) {
      logger.warn(`google-sa ${ctx.resource.name}: token exchange → ${up.statusCode}`);
      audit({ method: "POST", host, path: tokenUrl.pathname, status: up.statusCode, swap: "token" });
      return sendJson(res, up.statusCode, {
        error: json.error ?? "upstream_error",
        error_description: json.error_description,
      });
    }
    const fake = `${FAKE_GOOGLE_TOKEN_PREFIX}${randomBytes(32).toString("base64url")}`;
    const ttl = Number(json.expires_in ?? 3600);
    await TokenSwapModel.create({
      fakeHash: hashToken(fake),
      deviceId: ctx.deviceId,
      resourceId: ctx.resource.id,
      real: encryptSecret(masterKey(), accessToken),
      expiresAt: new Date(Date.now() + ttl * 1000),
    });
    audit({ method: "POST", host, path: tokenUrl.pathname, status: 200, swap: "token" });
    sendJson(res, 200, { ...json, access_token: fake });
  }

  async function forwardApi(req: GatewayRequest, res: GatewayResponse, host: string): Promise<void> {
    const bearer = /^Bearer\s+(\S+)$/i.exec(String(req.headers.authorization ?? ""))?.[1];
    if (!bearer?.startsWith(FAKE_GOOGLE_TOKEN_PREFIX)) {
      req.resume();
      return unauthenticated(res, "requests to Google APIs need an access token issued through cb");
    }
    const swap = await TokenSwapModel.findOne({
      fakeHash: hashToken(bearer),
      deviceId: ctx.deviceId,
      resourceId: ctx.resource.id,
      expiresAt: { $gt: new Date() },
    })
      .select("+real")
      .lean();
    if (!swap) {
      req.resume();
      return unauthenticated(res, "access token is unknown or expired for this device");
    }
    const realToken = decryptSecret(masterKey(), swap.real);
    const method = req.method ?? "GET";
    const upstream = upstreamFor(host);
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(req.headers)) {
      if (k.startsWith(":") || HOP_BY_HOP.has(k) || v === undefined) continue;
      headers[k] = Array.isArray(v) ? v.join(", ") : v;
    }
    headers.host = upstream.host;
    headers.authorization = `Bearer ${realToken}`;
    const up = await request(new URL(req.url ?? "/", upstream.origin), {
      method: method as "GET",
      headers,
      body: method === "GET" || method === "HEAD" ? undefined : (req as unknown as Readable),
      dispatcher: upstreamDispatcher(),
    });
    const out: Record<string, string | string[]> = {};
    for (const [k, v] of Object.entries(up.headers)) if (!HOP_BY_HOP.has(k) && v !== undefined) out[k] = v;
    const plain = decoded(up.body, out);
    (res as import("node:http").ServerResponse).writeHead(
      up.statusCode,
      redactHeaders(plain.headers, [realToken]),
    );
    await pipeline(plain.body, createRedactor(realToken), res as unknown as NodeJS.WritableStream);
    audit({ method, host, path: (req.url ?? "/").split("?")[0], status: up.statusCode, swap: "bearer" });
  }

  return (req: GatewayRequest, res: GatewayResponse) => {
    const host = (ctx.host ?? "").toLowerCase();
    const isToken =
      req.method === "POST" &&
      host === tokenUrl.hostname &&
      (req.url ?? "").split("?")[0] === tokenUrl.pathname;
    (isToken ? exchangeToken(req, res, host) : forwardApi(req, res, host)).catch((err: unknown) => {
      logger.warn(
        `google-sa ${ctx.resource.name}: upstream ${host} failed — ${err instanceof Error ? err.message : String(err)}`,
      );
      sendJson(res, 502, { error: "cb_upstream_unreachable" });
    });
  };
}
