import http, { type IncomingHttpHeaders } from "node:http";
import http2 from "node:http2";
import type { Readable } from "node:stream";
import { PassThrough } from "node:stream";
import { pipeline } from "node:stream/promises";
import zlib from "node:zlib";
import { request } from "undici";
import type { LeafCache } from "../../crypto/ca.js";
import { safeEqual } from "../../crypto/safe-equal.js";
import { recordAudit } from "../../services/audit.service.js";
import { fakeApiKey } from "../../services/fakes.service.js";
import { healthTap } from "../../services/resource-health.service.js";
import { learnFromResponse, paymentProviderOf } from "../../services/webhook-owner.service.js";
import { upstreamAllowed } from "../../utils/upstream-url.js";
import { asSocketLike } from "../socket-like.js";
import type { StreamAdapter, TunnelContext } from "../types.js";
import { createRedactor, redactHeaders } from "./redaction.js";
import { upstreamDispatcher } from "./upstream.js";

export type AuthScheme = "bearer" | "x-api-key" | "basic-password" | "header";
export type GatewayRequest = http.IncomingMessage | http2.Http2ServerRequest;
export type GatewayResponse = http.ServerResponse | http2.Http2ServerResponse;
export type Handler = (req: GatewayRequest, res: GatewayResponse) => void;

export interface HttpResourceConfig {
  upstreamUrl: string;
  authScheme?: AuthScheme;
  /** D12: header that carries the key when authScheme is "header" (lowercase). */
  authHeader?: string;
  fakePrefix?: string;
  basePath?: string;
  redirectHosts?: string[];
  /** OQ9: private-CA certificate and non-secret headers for every call. */
  caCert?: string;
  extraHeaders?: Record<string, string>;
  /** Preset that made the service (stripe, razorpay…); payment providers get webhook owner tracking. */
  provider?: string;
  /** Requests with another (public) key go through unchanged; a stand-in that isn't this device's is refused. */
  passOtherKeys?: boolean;
}

/** Larger responses are lists or files, never a created payment object. */
const LEARN_MAX_BYTES = 256 * 1024;

/**
 * FR-WH-002: copies (never delays) a payment API response so the objects it created can be linked to this
 * device; decompresses a copy when the SDK asked for gzip/deflate/br.
 */
function ownerTap(onBody: (body: Buffer) => void, encoding: string | undefined): PassThrough {
  const chunks: Buffer[] = [];
  let size = 0;
  const tap = new PassThrough();
  tap.on("data", (c: Buffer) => {
    size += c.length;
    if (size <= LEARN_MAX_BYTES) chunks.push(c);
  });
  tap.on("end", () => {
    if (size > LEARN_MAX_BYTES) return;
    const raw = Buffer.concat(chunks);
    const limit = { maxOutputLength: LEARN_MAX_BYTES * 8 };
    // Async: decompressing the copy must never block other connections.
    const decode: Record<string, (b: Buffer, cb: (err: Error | null, out: Buffer) => void) => void> = {
      gzip: (b, cb) => zlib.gunzip(b, limit, cb),
      deflate: (b, cb) => zlib.inflate(b, limit, cb),
      br: (b, cb) => zlib.brotliDecompress(b, limit, cb),
    };
    const fn = encoding ? decode[encoding.toLowerCase()] : undefined;
    if (!fn) return onBody(raw);
    fn(raw, (err, out) => {
      // Undecodable copy: nothing learned, the app's response is unaffected.
      if (!err) onBody(out);
    });
  });
  return tap;
}

export const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "host",
  "content-length",
]);

const first = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v);

function decodeBasic(header: string | undefined): [string, string] | undefined {
  const m = /^Basic\s+([A-Za-z0-9+/=]+)$/i.exec(header ?? "");
  if (!m?.[1]) return undefined;
  const decoded = Buffer.from(m[1], "base64").toString("utf8");
  const i = decoded.indexOf(":");
  return i < 0 ? undefined : [decoded.slice(0, i), decoded.slice(i + 1)];
}

export function extractCredential(
  scheme: AuthScheme,
  headers: IncomingHttpHeaders,
  authHeader?: string,
): string | undefined {
  if (scheme === "header") return authHeader ? first(headers[authHeader]) : undefined;
  if (scheme === "x-api-key") return first(headers["x-api-key"]);
  if (scheme === "bearer") return /^Bearer\s+(.+)$/i.exec(first(headers.authorization) ?? "")?.[1];
  return decodeBasic(first(headers.authorization))?.[1];
}

export function injectCredential(
  scheme: AuthScheme,
  headers: Record<string, string>,
  real: string,
  authHeader?: string,
): Record<string, string> {
  const out = { ...headers };
  if (scheme === "header" && authHeader) out[authHeader] = real;
  else if (scheme === "x-api-key") out["x-api-key"] = real;
  else if (scheme === "bearer") out.authorization = `Bearer ${real}`;
  else
    out.authorization = `Basic ${Buffer.from(`${decodeBasic(out.authorization)?.[0] ?? ""}:${real}`).toString("base64")}`;
  return out;
}

export function sendJson(res: GatewayResponse, status: number, body: unknown): void {
  if (res.headersSent) {
    res.destroy();
    return;
  }
  const text = JSON.stringify(body);
  // HTTP/1 and HTTP/2 compat responses share writeHead at runtime; their overload unions do not unify.
  (res as http.ServerResponse).writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(text),
  });
  res.end(text);
}

/** Verifies the device's fake key, swaps in the real one, streams the upstream response back redacted. */
export function createHttpHandler(ctx: TunnelContext): Handler {
  const config = ctx.resource.config as unknown as HttpResourceConfig;
  const scheme = config.authScheme ?? "bearer";
  const expected = fakeApiKey(
    { deviceId: ctx.deviceId, environmentId: ctx.environmentId, resourceId: ctx.resource.id },
    config.fakePrefix ?? "cb_",
  );
  const upstream = new URL(config.upstreamUrl);
  const prefix = upstream.pathname.replace(/\/$/, "");

  const fakePrefix = config.fakePrefix ?? "cb_";
  return (req, res) => {
    const presented = extractCredential(scheme, req.headers, config.authHeader);
    const own = Boolean(presented && safeEqual(presented, expected));
    // passOtherKeys: a public key (Supabase publishable) or none goes through untouched; any cb stand-in must be ours.
    const passThrough = !own && config.passOtherKeys === true && !(presented ?? "").startsWith(fakePrefix);
    if (!own && !passThrough) {
      req.resume();
      sendJson(res, 401, { error: "cb_invalid_credential" });
      return;
    }
    // OQ11: a service saved while plain http was allowed is refused once the server turns it off.
    if (!upstreamAllowed(config.upstreamUrl)) {
      req.resume();
      sendJson(res, 403, { error: "cb_upstream_not_allowed" });
      return;
    }
    const path = req.url ?? "/";
    const target = new URL(`${prefix}${path}`, upstream.origin);
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(req.headers)) {
      if (!k.startsWith(":") && !HOP_BY_HOP.has(k) && v !== undefined)
        headers[k] = Array.isArray(v) ? v.join(", ") : v;
    }
    const merged = { ...headers, ...(config.extraHeaders ?? {}) };
    const outHeaders: Record<string, string> = {
      // The service's headers win over the app's; the credential is injected last, so nothing overrides it.
      ...(passThrough ? merged : injectCredential(scheme, merged, ctx.secret, config.authHeader)),
      host: upstream.host,
    };
    // SDKs that send the key twice (Supabase: apikey + Authorization: Bearer) get the real key everywhere the
    // device's own stand-in appears — only that exact value is replaced.
    if (own)
      for (const [k, v] of Object.entries(outHeaders))
        if (k !== "host" && v.includes(expected)) outHeaders[k] = v.split(expected).join(ctx.secret);
    const method = req.method ?? "GET";
    request(target, {
      method: method as "GET",
      headers: outHeaders,
      body: method === "GET" || method === "HEAD" ? undefined : (req as unknown as Readable),
      dispatcher: upstreamDispatcher(config.caCert),
    })
      .then(async (up) => {
        const out: Record<string, string | string[]> = {};
        for (const [k, v] of Object.entries(up.headers))
          if (!HOP_BY_HOP.has(k) && v !== undefined) out[k] = v;
        (res as http.ServerResponse).writeHead(up.statusCode, redactHeaders(out, [ctx.secret]));
        const provider = paymentProviderOf(config);
        const learn =
          method === "POST" && provider && up.statusCode >= 200 && up.statusCode < 300
            ? ownerTap(
                (body) =>
                  learnFromResponse(
                    {
                      environmentId: ctx.environmentId,
                      deviceId: ctx.deviceId,
                      userId: ctx.userId,
                      provider,
                    },
                    path,
                    up.statusCode,
                    body,
                  ),
                typeof up.headers["content-encoding"] === "string"
                  ? up.headers["content-encoding"]
                  : undefined,
              )
            : undefined;
        // B11: what the provider said about the key (2xx ok, 401 rejected …), recorded without delaying the app.
        const tap = healthTap("http", up.statusCode, ctx.resource.id);
        const steps = [createRedactor(ctx.secret), ...(learn ? [learn] : []), ...(tap ? [tap] : [])];
        await pipeline([up.body, ...steps, res as unknown as NodeJS.WritableStream]);
        void recordAudit({
          orgId: ctx.orgId,
          actorId: ctx.userId,
          deviceId: ctx.deviceId,
          projectId: ctx.projectId,
          environmentId: ctx.environmentId,
          resourceId: ctx.resource.id,
          action: "http.request",
          meta: { method, host: upstream.host, path: path.split("?")[0], status: up.statusCode },
        });
      })
      .catch(() => sendJson(res, 502, { error: "cb_upstream_unreachable" }));
  };
}

/** Access lost before the tunnel opened: HTTP clients get the PRD's 403 (J7). */
export const deniedHandler: Handler = (req, res) => {
  req.resume();
  sendJson(res, 403, { error: "cb_access_revoked" });
};

export function serveHttp1(stream: Parameters<StreamAdapter>[0], handler: Handler): void {
  http.createServer(handler).emit("connection", asSocketLike(stream));
}

/** Layer 2: terminate the app's TLS with an org-CA leaf for the SNI host, then HTTP/2 or HTTP/1.1 by ALPN. */
export function serveTls(stream: Parameters<StreamAdapter>[0], leaves: LeafCache, handler: Handler): void {
  const server = http2.createSecureServer(
    {
      allowHTTP1: true,
      SNICallback: (servername, cb) => {
        leaves.context(servername).then(
          (c) => cb(null, c),
          (err: Error) => cb(err),
        );
      },
    },
    handler,
  );
  server.emit("connection", asSocketLike(stream));
}
