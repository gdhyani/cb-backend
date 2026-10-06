import { randomBytes } from "node:crypto";
import fs from "node:fs";
import type http from "node:http";
import https from "node:https";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import zlib from "node:zlib";
import { createCa, mintLeaf } from "../../src/crypto/ca.js";

const rand = () =>
  randomBytes(16)
    .toString("base64")
    .replace(/[^A-Za-z0-9]/g, "")
    .slice(0, 14);

/**
 * HTTPS stand-in for Stripe and Razorpay object creation (private CA). Accepts only the real keys and answers with
 * fresh object ids, like the real APIs — enough for the gateway to learn which device created what.
 */
export async function startMockPayments(opts: {
  stripeKey: string;
  razorpayKeyId: string;
  razorpaySecret: string;
}) {
  const ca = await createCa("cb test payments CA");
  const leaf = await mintLeaf(ca, "localhost");
  const caFile = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "cb-pay-ca-")), "ca.pem");
  fs.writeFileSync(caFile, ca.certPem);
  const basic = `Basic ${Buffer.from(`${opts.razorpayKeyId}:${opts.razorpaySecret}`).toString("base64")}`;
  /** Stripe webhook endpoints created through the API (Connect Stripe), by id. */
  const endpoints = new Map<string, { url: string; secret: string; events: string[] }>();
  let omitSecret = false;
  /** Stripe thin-payload event destinations (v2), by id. */
  const destinations = new Map<string, { url: string; secret: string; events: string[]; payload: string }>();
  /** Razorpay webhooks (v1 webhooks API), by id; no delete, like the real API. */
  const rzpHooks = new Map<
    string,
    { url: string; secret: string; events: Record<string, boolean>; active: boolean }
  >();
  /** Event names Razorpay knows (others are refused like the real API). */
  const RZP_KNOWN = new Set([
    "payment.authorized",
    "payment.captured",
    "payment.failed",
    "order.paid",
    "refund.created",
    "refund.processed",
    "refund.failed",
  ]);
  const privateHost = (u: string) => {
    try {
      const h = new URL(u).hostname;
      return h === "localhost" || /^(127\.|10\.|192\.168\.)/.test(h);
    } catch {
      return true;
    }
  };
  const server = https.createServer({ cert: leaf.certPem, key: leaf.keyPem }, (req, res) => {
    let raw = "";
    req.on("data", (c) => {
      raw += c;
    });
    req.on("end", () => handle(req, res, raw));
  });
  const handle = (req: http.IncomingMessage, res: http.ServerResponse, raw: string) => {
    // Like the real APIs: compressed when the client accepts it (the gateway must still learn the ids).
    const gzip = /\bgzip\b/.test(String(req.headers["accept-encoding"] ?? ""));
    const send = (status: number, body: unknown) => {
      const text = Buffer.from(JSON.stringify(body));
      res.writeHead(status, {
        "content-type": "application/json",
        ...(gzip ? { "content-encoding": "gzip" } : {}),
      });
      res.end(gzip ? zlib.gzipSync(text) : text);
    };
    const url = req.url ?? "";
    if (url.startsWith("/v2/core/event_destinations")) {
      if (req.headers.authorization !== `Bearer ${opts.stripeKey}`)
        return send(401, { error: { type: "invalid_request_error", message: "Invalid API Key provided" } });
      if (!req.headers["stripe-version"])
        return send(400, { error: { message: "Stripe-Version header required" } });
      const id = /^\/v2\/core\/event_destinations\/(ed_[A-Za-z0-9_]+)$/.exec(url)?.[1];
      const body = (raw ? JSON.parse(raw) : {}) as {
        enabled_events?: string[];
        include?: string[];
        event_payload?: string;
        webhook_endpoint?: { url?: string };
      };
      if (id) {
        const d = destinations.get(id);
        if (!d) return send(404, { error: { code: "not_found", message: "No such destination" } });
        if (req.method === "DELETE") {
          destinations.delete(id);
          return send(200, { id, deleted: true });
        }
        d.url = body.webhook_endpoint?.url ?? d.url;
        return send(200, { id, livemode: false, webhook_endpoint: { signing_secret: null, url: null } });
      }
      const events = (body.enabled_events ?? []) as string[];
      if (events.includes("*"))
        return send(400, {
          error: { message: "You passed invalid Event type(s) in the `enabled_events` parameter: `*`." },
        });
      const newId = `ed_test_${rand()}${rand()}`;
      const d = {
        url: body.webhook_endpoint?.url ?? "",
        secret: `whsec_${rand()}${rand()}`,
        events,
        payload: body.event_payload ?? "",
      };
      destinations.set(newId, d);
      const include = (body.include ?? []) as string[];
      return send(200, {
        id: newId,
        livemode: false,
        event_payload: d.payload,
        enabled_events: events,
        webhook_endpoint: {
          signing_secret: include.includes("webhook_endpoint.signing_secret") ? d.secret : null,
          url: null,
        },
      });
    }
    if (url.startsWith("/v1/webhooks")) {
      if (req.headers.authorization !== basic)
        return send(401, {
          error: { code: "BAD_REQUEST_ERROR", description: "The api key provided is invalid" },
        });
      const id = /^\/v1\/webhooks\/([A-Za-z0-9]+)$/.exec(url)?.[1];
      let body: { url?: string; secret?: string; active?: boolean; events?: unknown };
      try {
        body = raw ? JSON.parse(raw) : {};
      } catch {
        return send(400, { error: { description: "the json request could not be decoded" } });
      }
      if (req.method === "GET" && !id)
        return send(200, {
          entity: "collection",
          count: rzpHooks.size,
          items: [...rzpHooks].map(([i, h]) => ({
            id: i,
            url: h.url,
            active: h.active,
            secret_exists: true,
          })),
        });
      if (req.method === "DELETE") return send(404, {});
      if (body.events && (Array.isArray(body.events) || typeof body.events !== "object"))
        return send(400, { error: { description: "the json request could not be decoded" } });
      const given = (body.events ?? {}) as Record<string, unknown>;
      const names = Object.keys(given);
      const unknown = names.filter((n) => !RZP_KNOWN.has(n));
      if (unknown.length)
        return send(400, { error: { description: `Invalid event name/names: ${unknown.join(", ")}` } });
      if (body.url && privateHost(body.url))
        return send(400, {
          error: {
            description: `validation error : url: private ip found for host: ${new URL(body.url).hostname}.`,
          },
        });
      const events = Object.fromEntries(names.map((n) => [n, given[n] === "1"]));
      if (id) {
        const h = rzpHooks.get(id);
        if (!h || req.method !== "PUT") return send(404, {});
        Object.assign(h, { url: body.url ?? h.url, events, active: body.active ?? h.active });
        return send(200, { id, url: h.url, active: h.active, events: h.events });
      }
      if (req.method !== "POST") return send(404, {});
      if (!body.url || !body.secret)
        return send(400, { error: { description: "The url field is required." } });
      const newId = `Tk${rand()}`.slice(0, 14);
      rzpHooks.set(newId, { url: body.url, secret: body.secret, events, active: true });
      return send(200, { id: newId, url: body.url, active: true, events });
    }
    if (url.startsWith("/v1/webhook_endpoints")) {
      if (req.headers.authorization !== `Bearer ${opts.stripeKey}`)
        return send(401, { error: { type: "invalid_request_error", message: "Invalid API Key provided" } });
      const form = new URLSearchParams(raw);
      const existing = /^\/v1\/webhook_endpoints\/(we_[A-Za-z0-9]+)$/.exec(url)?.[1];
      if (existing) {
        const e = endpoints.get(existing);
        if (!e)
          return send(404, { error: { code: "resource_missing", message: "No such webhook endpoint" } });
        if (req.method === "DELETE") {
          endpoints.delete(existing);
          return send(200, { id: existing, deleted: true });
        }
        e.url = form.get("url") ?? e.url;
        return send(200, { id: existing, object: "webhook_endpoint", url: e.url });
      }
      const id = `we_${rand()}`;
      const e = {
        url: form.get("url") ?? "",
        secret: `whsec_${rand()}${rand()}`,
        events: form.getAll("enabled_events[]"),
      };
      endpoints.set(id, e);
      const omitted = omitSecret;
      omitSecret = false;
      return send(200, {
        id,
        object: "webhook_endpoint",
        url: e.url,
        enabled_events: e.events,
        secret: omitted ? undefined : e.secret,
      });
    }
    if (url.startsWith("/v1/payment_intents")) {
      if (req.headers.authorization !== `Bearer ${opts.stripeKey}`)
        return send(401, { error: { type: "auth" } });
      const confirm = /^\/v1\/payment_intents\/(pi_[A-Za-z0-9]+)\/confirm/.exec(url);
      if (confirm) return send(200, { id: confirm[1], status: "succeeded", latest_charge: `ch_${rand()}` });
      const id = `pi_${rand()}`;
      return send(200, {
        id,
        object: "payment_intent",
        client_secret: `${id}_secret_${rand()}`,
        customer: null,
      });
    }
    if (url.startsWith("/v1/orders")) {
      if (req.headers.authorization !== basic) return send(401, { error: { code: "BAD_REQUEST_ERROR" } });
      return send(200, { id: `order_${rand()}`, entity: "order", status: "created" });
    }
    send(404, { error: "not found" });
  };
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return {
    url: `https://localhost:${(server.address() as AddressInfo).port}`,
    caFile,
    endpoints,
    destinations,
    rzpHooks,
    /** The next endpoint create answers without `secret` (a malformed provider answer). */
    omitSecretOnce: () => {
      omitSecret = true;
    },
    close: () => server.close(),
  };
}
