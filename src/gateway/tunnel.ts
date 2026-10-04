import { randomUUID } from "node:crypto";
import type http from "node:http";
import type { Duplex } from "node:stream";
import type { Types } from "mongoose";
import { createWebSocketStream, WebSocket, WebSocketServer } from "ws";
import { z } from "zod";
import { LeafCache } from "../crypto/ca.js";
import { AppError } from "../errors/app-error.js";
import { bus } from "../events/bus.js";
import { logger } from "../logger/logger.js";
import { resolveDeviceToken } from "../middlewares/auth.middleware.js";
import { EnvironmentModel } from "../models/environment.model.js";
import { type ResourceKind, ResourceModel } from "../models/resource.model.js";
import { assertRuntimeAccess } from "../services/access.service.js";
import { recordAudit } from "../services/audit.service.js";
import { loadOrgCa } from "../services/org-ca.service.js";
import { DEFAULT_PROFILE, readProfileSecret, resolveProfile } from "../services/profile.service.js";
import { readResourceSecret } from "../services/resource.service.js";
import { eventConcerns, revalidate } from "../services/runtime-access.service.js";
import { createApnsHandler } from "./http/apns-adapter.js";
import { createAwsHandler } from "./http/aws-adapter.js";
import { createGoogleSaHandler } from "./http/google-sa-adapter.js";
import { createHostRouter } from "./http/host-router.js";
import { createHttpHandler, deniedHandler, type Handler, serveHttp1, serveTls } from "./http/http-adapter.js";
import { createOAuthHandler } from "./http/oauth-adapter.js";
import { mongodbAdapter } from "./mongodb/mongodb-adapter.js";
import { mysqlAdapter } from "./mysql/mysql-adapter.js";
import { postgresAdapter } from "./postgres/postgres-adapter.js";
import { redisAdapter } from "./redis/redis-adapter.js";
import { smtpAdapter } from "./smtp/smtp-adapter.js";
import { type AdapterHooks, type StreamAdapter, type TunnelContext, UpstreamError } from "./types.js";

export const TUNNEL_PATH = "/tunnel";

/** PRD §12.2 close codes. */
export const CloseCode = {
  Normal: 1000,
  GoingAway: 1001,
  Unauthorized: 4401,
  Forbidden: 4403,
  Revoked: 4410,
  UpstreamFailed: 4502,
} as const;

const Params = z.discriminatedUnion("layer", [
  z.object({
    layer: z.literal("1"),
    env: z.string().regex(/^[a-f0-9]{24}$/),
    resource: z.string().regex(/^[a-f0-9]{24}$/),
  }),
  z.object({
    layer: z.literal("2"),
    env: z.string().regex(/^[a-f0-9]{24}$/),
    host: z.string().min(1).max(253),
    port: z.coerce.number().int().min(1).max(65535),
  }),
]);

interface LiveTunnel {
  ctx: TunnelContext;
  ws: WebSocket;
  hooks: AdapterHooks;
}

const live = new Map<string, LiveTunnel>();
const leafCaches = new Map<string, Promise<LeafCache>>();

function leavesFor(orgId: Types.ObjectId): Promise<LeafCache> {
  const key = orgId.toHexString();
  let cache = leafCaches.get(key);
  if (!cache) {
    cache = loadOrgCa(orgId).then((ca) => new LeafCache(ca));
    cache.catch(() => leafCaches.delete(key));
    leafCaches.set(key, cache);
  }
  return cache;
}

const closeReason = (text: string) => text.slice(0, 120);

const STREAM_ADAPTERS: Partial<Record<ResourceKind, StreamAdapter>> = {
  redis: redisAdapter,
  mongodb: mongodbAdapter,
  postgres: postgresAdapter,
  mysql: mysqlAdapter,
  smtp: smtpAdapter,
};

/** HTTP-family kinds: served as HTTP (Layer 1) or TLS-terminated HTTP/1.1 + HTTP/2 (Layer 2). */
const HTTP_HANDLERS: Partial<Record<ResourceKind, (ctx: TunnelContext) => Handler>> = {
  http: createHttpHandler,
  oauth: createOAuthHandler,
  aws: createAwsHandler,
  "google-sa": createGoogleSaHandler,
  apns: createApnsHandler,
};

/** Kinds reachable through Layer 2 host redirection (aws is Layer 1 only). */
const LAYER2_KINDS: readonly ResourceKind[] = ["http", "oauth", "google-sa", "apns"];

async function handleTunnel(
  ws: WebSocket,
  stream: Duplex,
  req: http.IncomingMessage,
  url: URL,
): Promise<void> {
  const header = req.headers.authorization;
  const auth = header?.startsWith("Bearer ") ? await resolveDeviceToken(header.slice(7).trim()) : undefined;
  if (!auth?.deviceId) {
    ws.close(CloseCode.Unauthorized, "token invalid or expired");
    return;
  }
  const parsed = Params.safeParse(Object.fromEntries(url.searchParams));
  if (!parsed.success) {
    ws.close(CloseCode.Forbidden, "invalid tunnel parameters");
    return;
  }
  const params = parsed.data;
  const env = await EnvironmentModel.findById(params.env).lean();
  if (!env) {
    ws.close(CloseCode.Forbidden, "environment not found");
    return;
  }
  const hostPort = params.layer === "2" ? `${params.host.toLowerCase()}:${params.port}` : undefined;
  // Layer 2: every resource that claims this host; requests are routed among them (FR-GW-003).
  const candidates =
    params.layer === "1"
      ? await ResourceModel.find({ _id: params.resource, environmentId: env._id, disabledAt: null }).lean()
      : await ResourceModel.find({
          environmentId: env._id,
          kind: { $in: [...LAYER2_KINDS] },
          disabledAt: null,
          "config.redirectHosts": hostPort,
        })
          .sort({ createdAt: 1 })
          .lean();
  const resource = candidates[0];
  if (!resource) {
    ws.close(CloseCode.Forbidden, "no resource for this tunnel");
    return;
  }
  const audit = {
    orgId: env.orgId,
    actorId: auth.userId,
    deviceId: auth.deviceId,
    projectId: env.projectId,
    environmentId: env._id,
    resourceId: resource._id,
  };

  try {
    await assertRuntimeAccess(auth.userId, env, {
      deviceId: auth.deviceId,
      resourceId: resource._id.toHexString(),
    });
  } catch (err) {
    const code = err instanceof AppError ? err.code : "INTERNAL_ERROR";
    void recordAudit({ ...audit, action: "tunnel.denied", outcome: "denied", meta: { reason: code } });
    if (HTTP_HANDLERS[resource.kind as ResourceKind]) {
      // HTTP clients get a readable 403 instead of a dropped connection (J7).
      if (params.layer === "1") serveHttp1(stream, deniedHandler);
      else serveTls(stream, await leavesFor(env.orgId), deniedHandler);
      return;
    }
    ws.close(
      code === "ENVIRONMENT_KILLED" || code === "KILLSWITCH_ACTIVE" ? CloseCode.Revoked : CloseCode.Forbidden,
      closeReason(err instanceof Error ? err.message : "access denied"),
    );
    return;
  }

  /** Per-resource context: the real credential of the profile this user is assigned (FR-GW-005, J2). */
  const deviceId = auth.deviceId;
  const contextFor = async (r: (typeof candidates)[number]): Promise<TunnelContext | string> => {
    const profile = await resolveProfile(auth.userId, env._id.toHexString(), r._id.toHexString());
    const secret =
      profile === DEFAULT_PROFILE ? await readResourceSecret(r._id) : await readProfileSecret(r._id, profile);
    if (secret === undefined) return `credential profile "${profile}" no longer exists`;
    return {
      id: randomUUID(),
      layer: params.layer === "1" ? 1 : 2,
      userId: auth.userId,
      deviceId,
      environmentId: env._id.toHexString(),
      projectId: env.projectId.toHexString(),
      orgId: env.orgId.toHexString(),
      resource: {
        id: r._id.toHexString(),
        kind: r.kind as ResourceKind,
        name: r.name,
        config: (r.config as Record<string, unknown>) ?? {},
      },
      secret,
      profile,
      host: params.layer === "2" ? params.host : undefined,
      port: params.layer === "2" ? params.port : undefined,
    };
  };
  const contexts: TunnelContext[] = [];
  for (const r of candidates) {
    const c = await contextFor(r);
    if (typeof c === "string") {
      ws.close(CloseCode.Forbidden, closeReason(c));
      return;
    }
    contexts.push(c);
  }
  const ctx = contexts[0] as TunnelContext;
  const profile = ctx.profile;

  let bytesIn = 0;
  let bytesOut = 0;
  // Count on the socket's message events: a "data" listener would switch the paused stream to flowing.
  ws.on("message", (data: Buffer) => {
    bytesIn += data.length;
  });
  const send = ws.send.bind(ws);
  ws.send = ((data: Buffer, ...rest: unknown[]) => {
    bytesOut += data.length;
    return (send as (...a: unknown[]) => void)(data, ...rest);
  }) as typeof ws.send;

  const hooks: AdapterHooks = {};
  live.set(ctx.id, { ctx, ws, hooks });
  const openedAt = Date.now();
  void recordAudit({
    ...audit,
    action: "tunnel.opened",
    meta: {
      layer: ctx.layer,
      kind: resource.kind,
      host: ctx.host,
      profile,
      ...(contexts.length > 1 ? { sharedWith: contexts.slice(1).map((c) => c.resource.name) } : {}),
    },
  });
  logger.info(
    `tunnel ${ctx.id.slice(0, 8)} opened ${resource.kind}:${resource.name} layer=${ctx.layer} user=${auth.userId}`,
  );
  ws.on("close", (code) => {
    live.delete(ctx.id);
    for (const c of contexts) c.secret = "";
    void recordAudit({
      ...audit,
      action: "tunnel.closed",
      meta: { code, bytesIn, bytesOut, durationMs: Date.now() - openedAt },
    });
  });

  try {
    const createHandler = HTTP_HANDLERS[resource.kind as ResourceKind];
    if (createHandler) {
      const handler =
        contexts.length > 1
          ? createHostRouter(
              contexts.map((c) => ({
                ctx: c,
                handler: (HTTP_HANDLERS[c.resource.kind] ?? createHttpHandler)(c),
              })),
            )
          : createHandler(ctx);
      if (ctx.layer === 1) serveHttp1(stream, handler);
      else serveTls(stream, await leavesFor(env.orgId), handler);
      return;
    }
    const adapter = STREAM_ADAPTERS[resource.kind as ResourceKind];
    if (!adapter) throw new UpstreamError(`no adapter for ${resource.kind}`);
    await adapter(stream, ctx, hooks);
  } catch (err) {
    const summary = err instanceof UpstreamError ? err.message : "gateway error";
    logger.warn(`tunnel ${ctx.id.slice(0, 8)} → 4502 ${resource.kind}:${resource.name} — ${summary}`);
    if (!(err instanceof UpstreamError))
      logger.error(`tunnel ${ctx.id.slice(0, 8)} adapter failure`, {
        stack: err instanceof Error ? err.stack : undefined,
      });
    ws.close(CloseCode.UpstreamFailed, closeReason(summary));
  }
}

/** FR-GW-007: close every affected tunnel whose access no longer holds (re-checked from the DB, S3). */
function onBusEvent(event: Parameters<Parameters<typeof bus.subscribe>[0]>[0]): void {
  if (event.type !== "access.revoked") return;
  for (const tunnel of live.values()) {
    if (!eventConcerns(event, tunnel.ctx)) continue;
    void revalidate(tunnel.ctx).then((reason) => {
      if (!reason) return;
      const message = `access revoked (${event.reason})`;
      // Give the adapter a moment to send a protocol-native error first (bounded inside the adapter).
      void Promise.resolve(tunnel.hooks.onRevoke?.(message))
        .catch(() => undefined)
        .finally(() => tunnel.ws.close(CloseCode.Revoked, closeReason(message)));
      logger.info(`tunnel ${tunnel.ctx.id.slice(0, 8)} closed: ${reason}`);
    });
  }
}

export interface TunnelGateway {
  closeAll(): void;
  count(): number;
}

export function attachTunnel(server: http.Server): TunnelGateway {
  const wss = new WebSocketServer({ noServer: true, perMessageDeflate: false, maxPayload: 64 * 1024 * 1024 });
  server.on("upgrade", (req, socket, head) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    if (url.pathname !== TUNNEL_PATH) {
      socket.destroy();
      return;
    }
    // Accept first so the agent always receives a §12.2 close code.
    wss.handleUpgrade(req, socket, head, (ws) => {
      // Create the stream immediately: the client may send its first bytes before auth finishes.
      // A fresh readable buffers until a consumer attaches (no explicit pause(), which would block "data" listeners).
      const stream = createWebSocketStream(ws);
      stream.on("error", () => stream.destroy());
      handleTunnel(ws, stream, req, url).catch((err: unknown) => {
        logger.error("tunnel: unexpected failure", { stack: err instanceof Error ? err.stack : undefined });
        if (ws.readyState === WebSocket.OPEN) ws.close(CloseCode.UpstreamFailed, "gateway error");
      });
    });
  });
  const unsubscribe = bus.subscribe(onBusEvent);
  return {
    closeAll() {
      unsubscribe();
      for (const t of live.values()) t.ws.close(CloseCode.GoingAway, "server shutting down");
      for (const client of wss.clients) client.terminate();
    },
    count: () => live.size,
  };
}
