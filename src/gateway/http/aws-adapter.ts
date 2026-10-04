import type { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { Hash } from "@smithy/hash-node";
import { HttpRequest } from "@smithy/protocol-http";
import { SignatureV4 } from "@smithy/signature-v4";
import { request } from "undici";
import { safeEqual } from "../../crypto/safe-equal.js";
import { logger } from "../../logger/logger.js";
import { recordAudit } from "../../services/audit.service.js";
import { fakeAwsKeys } from "../../services/fakes.service.js";
import type { TunnelContext } from "../types.js";
import {
  type GatewayRequest,
  type GatewayResponse,
  type Handler,
  HOP_BY_HOP,
  sendJson,
} from "./http-adapter.js";
import { createRedactor } from "./redaction.js";
import { upstreamDispatcher } from "./upstream.js";

export interface AwsResourceConfig {
  region: string;
  /** Real service endpoint, e.g. https://s3.eu-west-1.amazonaws.com or an R2/MinIO-style URL. */
  endpoint: string;
}

interface RealKeys {
  accessKeyId: string;
  secretAccessKey: string;
}

const SIGNATURE_PARAMS = [
  "X-Amz-Algorithm",
  "X-Amz-Credential",
  "X-Amz-Date",
  "X-Amz-Expires",
  "X-Amz-SignedHeaders",
  "X-Amz-Signature",
  "X-Amz-Security-Token",
];
// Headers SigV4 must not sign (they change in transit or are set by the client stack).
const UNSIGNABLE = new Set([
  "authorization",
  "user-agent",
  "x-amzn-trace-id",
  "expect",
  "connection",
  "content-length",
  "transfer-encoding",
]);

/** Reads "Credential=AKID/20260101/eu-west-1/s3/aws4_request" from a header or query value. */
function parseCredential(
  value: string,
): { accessKeyId: string; region: string; service: string } | undefined {
  const m = /([A-Z0-9]{16,128})\/\d{8}\/([a-z0-9-]+)\/([a-z0-9-]+)\/aws4_request/i.exec(value);
  return m ? { accessKeyId: m[1] ?? "", region: m[2] ?? "", service: m[3] ?? "" } : undefined;
}

/**
 * §10.8 aws: the app signs with this device's fake AWS keys against the agent endpoint. The gateway checks the
 * access key, strips the fake signature and re-signs (header or presigned query) with the real keys for the
 * real endpoint. The request body is streamed through; its payload hash header is kept as the client sent it.
 */
export function createAwsHandler(ctx: TunnelContext): Handler {
  const config = ctx.resource.config as unknown as AwsResourceConfig;
  const endpoint = new URL(config.endpoint);
  const fake = fakeAwsKeys({
    deviceId: ctx.deviceId,
    environmentId: ctx.environmentId,
    resourceId: ctx.resource.id,
  });
  const real = JSON.parse(ctx.secret) as RealKeys;

  return (req: GatewayRequest, res: GatewayResponse) => {
    void (async () => {
      const incoming = new URL(req.url ?? "/", "http://agent.local");
      const method = req.method ?? "GET";
      const presigned = incoming.searchParams.has("X-Amz-Credential");
      const credential = parseCredential(
        presigned
          ? (incoming.searchParams.get("X-Amz-Credential") ?? "")
          : String(req.headers.authorization ?? ""),
      );
      if (!credential || !safeEqual(credential.accessKeyId, fake.accessKeyId)) {
        req.resume();
        sendJson(res, 403, {
          error: "cb_invalid_credential",
          message: "AWS access key is not valid for this device",
        });
        return;
      }

      const headers: Record<string, string> = {};
      for (const [k, v] of Object.entries(req.headers)) {
        if (k.startsWith(":") || HOP_BY_HOP.has(k) || UNSIGNABLE.has(k) || v === undefined) continue;
        if (k === "x-amz-date" || k === "x-amz-security-token") continue;
        headers[k] = Array.isArray(v) ? v.join(", ") : v;
      }
      headers.host = endpoint.host;
      const query: Record<string, string> = {};
      for (const [k, v] of incoming.searchParams) if (!SIGNATURE_PARAMS.includes(k)) query[k] = v;
      const basePath = endpoint.pathname.replace(/\/$/, "");
      const unsigned = new HttpRequest({
        method,
        protocol: endpoint.protocol,
        hostname: endpoint.hostname,
        port: endpoint.port ? Number(endpoint.port) : undefined,
        path: `${basePath}${incoming.pathname}`,
        query,
        headers,
      });
      const signer = new SignatureV4({
        credentials: real,
        region: credential.region || config.region,
        service: credential.service || "s3",
        sha256: Hash.bind(null, "sha256"),
        uriEscapePath: credential.service !== "s3",
      });

      let signed: HttpRequest;
      if (presigned) {
        // Presigned URLs sign only host (as the SDK does); other headers pass through unsigned.
        const expiresIn = Number(incoming.searchParams.get("X-Amz-Expires") ?? 900);
        // Query auth uses UNSIGNED-PAYLOAD; the header only feeds the hash and is not signed or sent.
        const hostOnly = new HttpRequest({
          ...unsigned,
          headers: { host: endpoint.host, "x-amz-content-sha256": "UNSIGNED-PAYLOAD" },
        });
        signed = (await signer.presign(hostOnly, {
          expiresIn,
          unsignableHeaders: new Set(["x-amz-content-sha256"]),
        })) as HttpRequest;
        const { "x-amz-content-sha256": _hash, ...presignedHeaders } = signed.headers;
        signed.headers = { ...headers, ...presignedHeaders };
      } else {
        // Keep the client's payload hash (e.g. UNSIGNED-PAYLOAD, a hex digest, or a streaming marker) so the body can stream.
        if (!headers["x-amz-content-sha256"]) unsigned.headers["x-amz-content-sha256"] = "UNSIGNED-PAYLOAD";
        signed = (await signer.sign(unsigned)) as HttpRequest;
      }

      const qs = new URLSearchParams(signed.query as Record<string, string>).toString();
      const target = `${endpoint.protocol}//${endpoint.host}${signed.path}${qs ? `?${qs}` : ""}`;
      const outHeaders = { ...signed.headers } as Record<string, string>;
      const length = req.headers["content-length"];
      if (typeof length === "string") outHeaders["content-length"] = length;
      try {
        const up = await request(target, {
          method: method as "GET",
          headers: outHeaders,
          body: method === "GET" || method === "HEAD" ? undefined : (req as unknown as Readable),
          dispatcher: upstreamDispatcher(),
        });
        const out: Record<string, string | string[]> = {};
        for (const [k, v] of Object.entries(up.headers))
          if (!HOP_BY_HOP.has(k) && v !== undefined) out[k] = v;
        if (up.headers["content-length"] !== undefined && method === "HEAD")
          out["content-length"] = String(up.headers["content-length"]);
        (res as import("node:http").ServerResponse).writeHead(up.statusCode, out);
        await pipeline(
          up.body,
          createRedactor(real.secretAccessKey),
          res as unknown as NodeJS.WritableStream,
        );
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
            host: endpoint.host,
            path: incoming.pathname,
            status: up.statusCode,
            service: credential.service,
          },
        });
      } catch (err) {
        logger.warn(
          `aws ${ctx.resource.name}: upstream request to ${endpoint.host} failed — ${err instanceof Error ? err.message : String(err)}`,
        );
        sendJson(res, 502, { error: "cb_upstream_unreachable" });
      }
    })();
  };
}
