import { Readable } from "node:stream";
import type { TunnelContext } from "../types.js";
import { FAKE_GOOGLE_TOKEN_PREFIX } from "./google-sa-adapter.js";
import { type GatewayRequest, type GatewayResponse, type Handler, sendJson } from "./http-adapter.js";
import { OAUTH_FAKE_PREFIX } from "./oauth-adapter.js";

export interface RoutedResource {
  ctx: TunnelContext;
  handler: Handler;
}

const MAX_SNIFF_BYTES = 1024 * 1024;

const first = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v) ?? "";

/** The presented credential, from Authorization (Bearer/Basic) or x-api-key. */
function presentedKeys(req: GatewayRequest): string[] {
  const keys: string[] = [];
  const auth = first(req.headers.authorization);
  const bearer = /^bearer\s+(\S+)/i.exec(auth)?.[1];
  if (bearer) keys.push(bearer);
  const basic = /^basic\s+(\S+)/i.exec(auth)?.[1];
  if (basic) {
    const [user = "", pass = ""] = Buffer.from(basic, "base64").toString("utf8").split(":");
    keys.push(decodeURIComponent(user), decodeURIComponent(pass));
  }
  const apiKey = first(req.headers["x-api-key"]);
  if (apiKey) keys.push(apiKey);
  return keys;
}

/** Header-only decision; undefined when the body has to be read (token endpoints). */
function matchByHeaders(req: GatewayRequest, resources: RoutedResource[]): RoutedResource | undefined {
  const keys = presentedKeys(req);
  const byKind = (kind: string) => resources.find((r) => r.ctx.resource.kind === kind);
  if (keys.some((k) => k.startsWith(FAKE_GOOGLE_TOKEN_PREFIX))) return byKind("google-sa");
  if ((req.url ?? "").startsWith("/3/device/")) return byKind("apns");
  // API-key resources: the fake key carries the resource's configured prefix.
  for (const r of resources.filter((x) => x.ctx.resource.kind === "http")) {
    const prefix = String(r.ctx.resource.config.fakePrefix ?? "cb_");
    if (keys.some((k) => k.startsWith(prefix) && !k.startsWith(OAUTH_FAKE_PREFIX))) return r;
  }
  return undefined;
}

/** Token endpoints: jwt-bearer assertions belong to a service account, client secrets to an OAuth client. */
function matchByForm(
  body: string,
  req: GatewayRequest,
  resources: RoutedResource[],
): RoutedResource | undefined {
  const form = new URLSearchParams(body);
  const byKind = (kind: string) => resources.find((r) => r.ctx.resource.kind === kind);
  if (form.get("grant_type") === "urn:ietf:params:oauth:grant-type:jwt-bearer") return byKind("google-sa");
  if (form.has("client_secret") || /^basic\s+/i.test(first(req.headers.authorization)))
    return byKind("oauth");
  return undefined;
}

/** A request whose body was already read, replayed as a fresh stream for the chosen handler. */
function replay(req: GatewayRequest, body: Buffer): GatewayRequest {
  const copy = Readable.from(body.length ? [body] : []) as unknown as Record<string, unknown>;
  for (const key of [
    "headers",
    "method",
    "url",
    "httpVersion",
    "socket",
    "rawHeaders",
    "authority",
    "scheme",
  ])
    copy[key] = (req as unknown as Record<string, unknown>)[key];
  return copy as unknown as GatewayRequest;
}

/**
 * FR-GW-003: several resources may claim the same redirected host (e.g. Google OAuth and Firebase on
 * oauth2.googleapis.com). Each request goes to the resource whose fake credential it carries; requests that
 * carry none fall through to the OAuth client (which forwards untouched requests as-is) or the first resource.
 */
export function createHostRouter(resources: RoutedResource[]): Handler {
  const fallback = resources.find((r) => r.ctx.resource.kind === "oauth") ?? resources[0];
  return (req: GatewayRequest, res: GatewayResponse) => {
    const byHeaders = matchByHeaders(req, resources);
    if (byHeaders) return byHeaders.handler(req, res);
    const type = first(req.headers["content-type"]);
    if (req.method !== "POST" || !type.includes("application/x-www-form-urlencoded"))
      return fallback?.handler(req, res);
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > MAX_SNIFF_BYTES) {
        req.removeAllListeners("data");
        req.resume();
        sendJson(res, 413, { error: "cb_request_too_large" });
        return;
      }
      chunks.push(Buffer.from(c));
    });
    req.on("end", () => {
      if (size > MAX_SNIFF_BYTES) return;
      const body = Buffer.concat(chunks);
      const target = matchByForm(body.toString("utf8"), req, resources) ?? fallback;
      target?.handler(replay(req, body), res);
    });
  };
}
