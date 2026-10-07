import type { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { request } from "undici";
import { safeEqual } from "../../crypto/safe-equal.js";
import { logger } from "../../logger/logger.js";
import { recordAudit } from "../../services/audit.service.js";
import { fakeApiKey } from "../../services/fakes.service.js";
import { DEFAULT_PROFILE } from "../../services/profile.service.js";
import { healthTap } from "../../services/resource-health.service.js";
import type { TunnelContext } from "../types.js";
import {
  type GatewayRequest,
  type GatewayResponse,
  type Handler,
  HOP_BY_HOP,
  sendJson,
} from "./http-adapter.js";
import { createRedactor, decoded, injectedBasic, redactHeaders } from "./redaction.js";
import { upstreamDispatcher } from "./upstream.js";

export interface OAuthResourceConfig {
  /** Full token endpoint, e.g. https://oauth2.googleapis.com/token */
  tokenUrl: string;
  /** Where requests are actually sent (defaults to the token URL's origin). */
  upstreamUrl?: string;
  fakePrefix?: string;
  redirectHosts?: string[];
}

export const OAUTH_FAKE_PREFIX = "cb-";

export async function readBody(req: GatewayRequest): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of req as unknown as AsyncIterable<Buffer>) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks);
}

/**
 * §10.8 oauth: on POST to the token endpoint, verify the device's fake client secret (form field
 * `client_secret` or HTTP Basic) and replace it with the real one. Every other request passes through unchanged.
 */
export function createOAuthHandler(ctx: TunnelContext): Handler {
  const config = ctx.resource.config as unknown as OAuthResourceConfig;
  const tokenUrl = new URL(config.tokenUrl);
  const upstream = new URL(config.upstreamUrl ?? tokenUrl.origin);
  const expected = fakeApiKey(
    { deviceId: ctx.deviceId, environmentId: ctx.environmentId, resourceId: ctx.resource.id },
    config.fakePrefix ?? OAUTH_FAKE_PREFIX,
  );

  return (req: GatewayRequest, res: GatewayResponse) => {
    void (async () => {
      const path = req.url ?? "/";
      const method = req.method ?? "GET";
      const headers: Record<string, string> = {};
      for (const [k, v] of Object.entries(req.headers)) {
        if (!k.startsWith(":") && !HOP_BY_HOP.has(k) && v !== undefined)
          headers[k] = Array.isArray(v) ? v.join(", ") : v;
      }
      // Host follows where the request is really sent (TLS is verified against it).
      headers.host = upstream.host;
      let body: Buffer | Readable | undefined =
        method === "GET" || method === "HEAD" ? undefined : (req as unknown as Readable);
      let swapped = false;

      if (method === "POST" && path.split("?")[0] === tokenUrl.pathname) {
        const raw = await readBody(req);
        const basic = /^Basic\s+(.+)$/i.exec(headers.authorization ?? "");
        if (basic?.[1]) {
          const [id = "", secret = ""] = Buffer.from(basic[1], "base64").toString("utf8").split(":");
          if (!safeEqual(decodeURIComponent(secret), expected))
            return sendJson(res, 401, {
              error: "invalid_client",
              error_description: "cb: client secret not valid for this device",
            });
          headers.authorization = `Basic ${Buffer.from(`${id}:${encodeURIComponent(ctx.secret)}`).toString("base64")}`;
          swapped = true;
          body = raw;
        } else {
          const form = new URLSearchParams(raw.toString("utf8"));
          const presented = form.get("client_secret");
          if (presented !== null) {
            if (!safeEqual(presented, expected))
              return sendJson(res, 401, {
                error: "invalid_client",
                error_description: "cb: client secret not valid for this device",
              });
            form.set("client_secret", ctx.secret);
            swapped = true;
          }
          body = Buffer.from(form.toString());
        }
        headers["content-length"] = String((body as Buffer).length);
      }

      const target = new URL(`${upstream.pathname.replace(/\/$/, "")}${path}`, upstream.origin);
      try {
        const up = await request(target, {
          method: method as "GET",
          headers,
          body,
          dispatcher: upstreamDispatcher(),
        });
        const out: Record<string, string | string[]> = {};
        for (const [k, v] of Object.entries(up.headers))
          if (!HOP_BY_HOP.has(k) && v !== undefined) out[k] = v;
        const plain = decoded(up.body, out);
        const secrets = [ctx.secret, ...injectedBasic(headers.authorization)];
        (res as import("node:http").ServerResponse).writeHead(
          up.statusCode,
          redactHeaders(plain.headers, secrets),
        );
        const tap =
          swapped && ctx.profile === DEFAULT_PROFILE
            ? healthTap("oauth", up.statusCode, ctx.resource.id, ctx.resource.keyVersion)
            : undefined;
        await pipeline([
          plain.body,
          createRedactor(secrets),
          ...(tap ? [tap] : []),
          res as unknown as NodeJS.WritableStream,
        ]);
        if (swapped) {
          void recordAudit({
            orgId: ctx.orgId,
            actorId: ctx.userId,
            deviceId: ctx.deviceId,
            projectId: ctx.projectId,
            environmentId: ctx.environmentId,
            resourceId: ctx.resource.id,
            action: "http.request",
            meta: {
              method,
              host: tokenUrl.host,
              path: tokenUrl.pathname,
              status: up.statusCode,
              oauth: true,
            },
          });
        }
      } catch (err) {
        logger.warn(
          `oauth ${ctx.resource.name}: upstream request to ${target.host} failed — ${err instanceof Error ? err.message : String(err)}`,
        );
        sendJson(res, 502, { error: "cb_upstream_unreachable" });
      }
    })();
  };
}
