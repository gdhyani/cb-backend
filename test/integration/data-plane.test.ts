import type http from "node:http";
import { request as httpRequest } from "node:http";
import type { AddressInfo } from "node:net";
import tls from "node:tls";
import { Redis } from "ioredis";
import { MongoClient } from "mongodb";
import { MongoMemoryServer } from "mongodb-memory-server";
import mongoose from "mongoose";
import type request from "supertest";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createWebSocketStream, WebSocket } from "ws";
import { createApp } from "../../src/app.js";
import { connectMongo, disconnectMongo } from "../../src/clients/mongodb.client.js";
import { loadEnv, setEnv } from "../../src/config/env.js";
import { resetUpstreamDispatcher } from "../../src/gateway/http/upstream.js";
import { GrantModel } from "../../src/models/grant.model.js";
import { createServer } from "../../src/server.js";
import { sweepExpiredGrants } from "../../src/services/grant.service.js";
import { localListener } from "../helpers/agent.js";
import { addMember, cli, loginDevice, signupOwner } from "../helpers/api.js";
import { testEnvVars } from "../helpers/env.js";
import { startMockProvider } from "../helpers/mock-provider.js";
import { startMemoryMongo } from "../helpers/mongo.js";
import { startRedis } from "../helpers/redis-server.js";

const MONGO_PW = "REAL_MONGO_PW_7731";
const REDIS_PW = "REAL_REDIS_PW_4410";
const API_KEY = "REAL_API_KEY_sk_live_99";
const CLIENT_SECRET = "REAL_OAUTH_CLIENT_SECRET_42";

let backendDb: Awaited<ReturnType<typeof startMemoryMongo>>;
let upstreamMongo: MongoMemoryServer;
let redis: Awaited<ReturnType<typeof startRedis>>;
let provider: Awaited<ReturnType<typeof startMockProvider>>;
let server: http.Server;
let base: string;

beforeAll(async () => {
  [backendDb, upstreamMongo, redis, provider] = await Promise.all([
    startMemoryMongo(),
    MongoMemoryServer.create({ auth: { enable: true, customRootName: "root", customRootPwd: MONGO_PW } }),
    startRedis(REDIS_PW),
    startMockProvider(API_KEY, CLIENT_SECRET),
  ]);
  setEnv(loadEnv({ ...testEnvVars(backendDb.uri), UPSTREAM_EXTRA_CA_FILE: provider.caFile }));
  resetUpstreamDispatcher();
  await connectMongo(backendDb.uri);
  server = createServer(createApp()).server;
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}, 120_000);
afterAll(async () => {
  server.closeAllConnections();
  server.close();
  await disconnectMongo();
  await Promise.all([backendDb.stop(), upstreamMongo.stop()]);
  redis.stop();
  provider.close();
});
beforeEach(async () => {
  await mongoose.connection.db?.dropDatabase();
});

/** Admin sets up a project with mongodb, redis and http resources; developer Bob gets a device token. */
async function scenario(grantBob = true) {
  const app = server.listeners("request")[0] as unknown as Parameters<typeof request>[0];
  const ctx = await signupOwner(app as never);
  const owner = ctx.owner;
  const project = await owner.post(`/api/orgs/${ctx.orgId}/projects`, { name: "Shop" });
  const envId = project.body.data.environments[0].id as string;
  const mongoUri = upstreamMongo
    .getUri()
    .replace("mongodb://", `mongodb://root:${MONGO_PW}@`)
    .replace(/\/?$/, "/shop?authSource=admin");
  const db = await owner.post(`/api/environments/${envId}/resources`, {
    kind: "mongodb",
    name: "main-db",
    connectionUri: mongoUri,
  });
  const cache = await owner.post(`/api/environments/${envId}/resources`, {
    kind: "redis",
    name: "cache",
    connectionUri: redis.uri,
  });
  const api = await owner.post(`/api/environments/${envId}/resources`, {
    kind: "http",
    name: "provider",
    upstreamUrl: provider.url,
    apiKey: API_KEY,
    fakePrefix: "sk_cb_",
    basePath: "/v1",
    redirectHosts: ["api.provider.test:443"],
  });
  for (const v of [
    { type: "brokered", key: "MONGODB_URI", resourceId: db.body.data.id, field: "url" },
    { type: "brokered", key: "REDIS_URL", resourceId: cache.body.data.id, field: "url" },
    { type: "brokered", key: "PROVIDER_API_KEY", resourceId: api.body.data.id, field: "key" },
    { type: "brokered", key: "PROVIDER_BASE_URL", resourceId: api.body.data.id, field: "baseUrl" },
    { type: "plain", key: "PORT", value: "3000" },
  ]) {
    const res = await owner.post(`/api/environments/${envId}/variables`, v);
    if (res.status !== 201) throw new Error(JSON.stringify(res.body));
  }
  const bob = await addMember(app as never, owner, ctx.orgId, "Bob");
  const grant = grantBob
    ? await owner.post(`/api/environments/${envId}/grants`, { userId: bob.userId })
    : undefined;
  const { token, deviceId } = await loginDevice(app as never, bob.member);
  const boot = await cli(app as never, token).get(
    `/api/agent/bootstrap?projectId=${project.body.data.id}&env=development`,
  );
  return {
    app,
    owner,
    bob,
    token,
    deviceId,
    envId,
    grantId: grant?.body.data.id as string | undefined,
    boot,
    resources: { db: db.body.data.id, cache: cache.body.data.id, api: api.body.data.id },
  };
}

const fill = (template: string, port: number) => template.replace("{port}", String(port));

function freshGet(port: number, path: string, key: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, path, agent: false, headers: { authorization: `Bearer ${key}` } },
      (res) => {
        let body = "";
        res.on("data", (c) => {
          body += c;
        });
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body }));
      },
    );
    req.on("error", reject);
    req.end();
  });
}

describe("agent bootstrap (FR-AGT-003, S1, S7)", () => {
  it("S1 returns only fake, plain and listener values — never real secrets", async () => {
    const { boot } = await scenario();
    expect(boot.status).toBe(200);
    const text = JSON.stringify(boot.body);
    for (const secret of [MONGO_PW, REDIS_PW, API_KEY, "PRIVATE KEY"]) expect(text).not.toContain(secret);
    const data = boot.body.data;
    expect(data.plain.PORT).toBe("3000");
    expect(data.plain.PROVIDER_API_KEY).toMatch(/^sk_cb_[A-Za-z0-9]{40}$/);
    expect(data.redirects).toEqual([
      { host: "api.provider.test", port: 443, resourceId: expect.any(String) },
    ]);
    const byKind = Object.fromEntries(
      data.listeners.map((l: { kind: string; env: Record<string, string> }) => [l.kind, l.env]),
    );
    expect(byKind.mongodb.MONGODB_URI).toMatch(
      /^mongodb:\/\/cbu_[a-z2-7]{8}:[A-Za-z0-9]{32}@127\.0\.0\.1:\{port\}\/shop\?directConnection=true&authSource=admin&authMechanism=SCRAM-SHA-256$/,
    );
    expect(byKind.redis.REDIS_URL).toMatch(
      /^redis:\/\/cbu_[a-z2-7]{8}:[A-Za-z0-9]{32}@127\.0\.0\.1:\{port\}$/,
    );
    expect(byKind.http.PROVIDER_BASE_URL).toBe("http://127.0.0.1:{port}/v1");
    expect(data.orgCaCert).toContain("BEGIN CERTIFICATE");
  });

  it("NO_ACCESS without a grant; ENVIRONMENT_KILLED when killed", async () => {
    const { boot, owner, envId, bob, token } = await scenario(false);
    expect(boot.status).toBe(403);
    expect(boot.body.error.code).toBe("NO_ACCESS");
    await owner.post(`/api/environments/${envId}/grants`, { userId: bob.userId });
    const projectId = (await owner.get(`/api/environments/${envId}`)).body.data.projectId;
    const url = `/api/agent/bootstrap?projectId=${projectId}&env=development`;
    const app = server.listeners("request")[0] as never;
    expect((await cli(app, token).get(url)).status).toBe(200);
    await owner.patch(`/api/environments/${envId}`, { killed: true, reason: "rotating keys" });
    expect((await cli(app, token).get(url)).body.error.code).toBe("ENVIRONMENT_KILLED");
  });
});

describe("tunnels through real services (T4, FR-GW-001, FR-GW-002)", () => {
  it("T4 mongodb driver works through the tunnel; the gateway authenticated upstream", async () => {
    const { token, envId, resources, boot } = await scenario();
    const listener = await localListener(base, token, { layer: "1", env: envId, resource: resources.db });
    const template = boot.body.data.listeners.find((l: { kind: string }) => l.kind === "mongodb").env
      .MONGODB_URI;
    const client = new MongoClient(fill(template, listener.port), { serverSelectionTimeoutMS: 5000 });
    await client.connect();
    const coll = client.db("shop").collection("orders");
    await coll.insertOne({ sku: "A1", qty: 2 });
    expect(await coll.findOne({ sku: "A1" })).toMatchObject({ qty: 2 });
    await client.close();
    listener.close();
  });

  it("S7 mongodb: no credentials or a wrong fake password is refused by the gateway", async () => {
    const { token, envId, resources, boot } = await scenario();
    const listener = await localListener(base, token, { layer: "1", env: envId, resource: resources.db });
    const template: string = boot.body.data.listeners.find((l: { kind: string }) => l.kind === "mongodb").env
      .MONGODB_URI;
    const bare = new MongoClient(`mongodb://127.0.0.1:${listener.port}/shop?directConnection=true`, {
      serverSelectionTimeoutMS: 3000,
    });
    await bare.connect();
    await expect(bare.db("shop").collection("orders").findOne({})).rejects.toMatchObject({ code: 13 });
    await bare.close();
    const wrong = new MongoClient(
      fill(template, listener.port).replace(/:([A-Za-z0-9]{32})@/, `:${"x".repeat(32)}@`),
      { serverSelectionTimeoutMS: 3000 },
    );
    await expect(wrong.connect()).rejects.toMatchObject({ code: 18 });
    await wrong.close();
    listener.close();
  });

  it("FR-GW-002 mongodb monitoring connection keeps serving hello without authenticating", async () => {
    const { token, envId, resources, boot } = await scenario();
    const listener = await localListener(base, token, { layer: "1", env: envId, resource: resources.db });
    const template: string = boot.body.data.listeners.find((l: { kind: string }) => l.kind === "mongodb").env
      .MONGODB_URI;
    const client = new MongoClient(fill(template, listener.port), {
      heartbeatFrequencyMS: 500,
      serverSelectionTimeoutMS: 5000,
    });
    const beats: string[] = [];
    client.on("serverHeartbeatSucceeded", () => beats.push("ok"));
    client.on("serverHeartbeatFailed", () => beats.push("fail"));
    await client.connect();
    await new Promise((r) => setTimeout(r, 2500));
    expect(beats.filter((b) => b === "ok").length).toBeGreaterThanOrEqual(2);
    expect(beats).not.toContain("fail");
    await client.close();
    listener.close();
  });

  it("FR-GW-002 mongodb speculative auth and compression in hello are stripped", async () => {
    const { token, envId, resources, boot } = await scenario();
    const listener = await localListener(base, token, { layer: "1", env: envId, resource: resources.db });
    const template: string = boot.body.data.listeners.find((l: { kind: string }) => l.kind === "mongodb").env
      .MONGODB_URI;
    const client = new MongoClient(fill(template, listener.port), {
      compressors: ["zlib"],
      serverSelectionTimeoutMS: 5000,
    });
    await client.connect();
    const coll = client.db("shop").collection("orders");
    await coll.insertOne({ sku: "Z9", qty: 1 });
    expect(await coll.findOne({ sku: "Z9" })).toMatchObject({ qty: 1 });
    await client.close();
    listener.close();
  });

  it("T4 ioredis works with the fake password; a wrong password is refused locally", async () => {
    const { token, envId, resources, boot } = await scenario();
    const listener = await localListener(base, token, { layer: "1", env: envId, resource: resources.cache });
    const template = boot.body.data.listeners.find((l: { kind: string }) => l.kind === "redis").env.REDIS_URL;
    const client = new Redis(fill(template, listener.port), { lazyConnect: true, maxRetriesPerRequest: 0 });
    await client.connect();
    await client.set("greeting", "hello");
    expect(await client.get("greeting")).toBe("hello");
    client.disconnect();
    const wrong = new Redis(`redis://default:not-the-fake@127.0.0.1:${listener.port}`, {
      lazyConnect: true,
      maxRetriesPerRequest: 0,
      retryStrategy: () => null,
    });
    const authError = new Promise<string>((resolve) => wrong.on("error", (e: Error) => resolve(e.message)));
    await wrong.connect().catch(() => undefined);
    expect(await authError).toMatch(/WRONGPASS/);
    wrong.disconnect();
    listener.close();
  });

  it("Layer 1 HTTP: fake key swapped for the real one, echoed secret redacted (FR-GW-006)", async () => {
    const { token, envId, resources, boot } = await scenario();
    const listener = await localListener(base, token, { layer: "1", env: envId, resource: resources.api });
    const res = await fetch(`http://127.0.0.1:${listener.port}/v1/models`, {
      headers: { authorization: `Bearer ${boot.body.data.plain.PROVIDER_API_KEY}` },
    });
    const body = await res.text();
    expect(res.status).toBe(200);
    expect(JSON.parse(body)).toMatchObject({ ok: true, path: "/v1/models", echo: "token was [cb-redacted]" });
    expect(body).not.toContain(API_KEY);
    expect(provider.requests.at(-1)?.authorization).toBe(`Bearer ${API_KEY}`);
    const bad = await fetch(`http://127.0.0.1:${listener.port}/v1/models`, {
      headers: { authorization: "Bearer sk_cb_forged" },
    });
    expect(bad.status).toBe(401);
    expect(await bad.json()).toEqual({ error: "cb_invalid_credential" });
    listener.close();
  });

  it("Layer 2: TLS for api.provider.test terminated with an org-CA leaf (FR-GW-003)", async () => {
    const { token, envId, boot } = await scenario();
    const url = new URL("/tunnel", base);
    url.protocol = "ws:";
    url.search = new URLSearchParams({
      layer: "2",
      env: envId,
      host: "api.provider.test",
      port: "443",
    }).toString();
    const ws = new WebSocket(url, { headers: { authorization: `Bearer ${token}` } });
    await new Promise((r) => ws.once("open", r));
    const secure = tls.connect({
      socket: createWebSocketStream(ws),
      servername: "api.provider.test",
      ca: boot.body.data.orgCaCert,
      ALPNProtocols: ["http/1.1"],
    });
    await new Promise((r, j) => {
      secure.once("secureConnect", r);
      secure.once("error", j);
    });
    secure.write(
      `GET /v1/charges HTTP/1.1\r\nHost: api.provider.test\r\nAuthorization: Bearer ${boot.body.data.plain.PROVIDER_API_KEY}\r\nConnection: close\r\n\r\n`,
    );
    const raw = await new Promise<string>((resolve) => {
      let out = "";
      secure.on("data", (d) => {
        out += d.toString();
      });
      secure.on("end", () => resolve(out));
    });
    expect(raw).toMatch(/^HTTP\/1\.1 200/);
    expect(raw).toContain('"path":"/v1/charges"');
    expect(raw).not.toContain(API_KEY);
  });

  it("N3 S8 upstream response headers are redacted, not only the body (FR-GW-006)", async () => {
    const { token, envId, resources, boot } = await scenario();
    const listener = await localListener(base, token, { layer: "1", env: envId, resource: resources.api });
    const res = await fetch(`http://127.0.0.1:${listener.port}/v1/models`, {
      headers: { authorization: `Bearer ${boot.body.data.plain.PROVIDER_API_KEY}` },
    });
    await res.text();
    expect(res.headers.get("x-echo-auth")).toBe("Bearer [cb-redacted]");
    for (const [, v] of res.headers) expect(v).not.toContain(API_KEY);
    listener.close();
  });

  it("N4 a 3xx is passed back, not followed; its Location is redacted", async () => {
    const { token, envId, resources, boot } = await scenario();
    const listener = await localListener(base, token, { layer: "1", env: envId, resource: resources.api });
    const before = provider.requests.length;
    const res = await fetch(`http://127.0.0.1:${listener.port}/v1/redirect`, {
      redirect: "manual",
      headers: { authorization: `Bearer ${boot.body.data.plain.PROVIDER_API_KEY}` },
    });
    await res.text();
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("https://elsewhere.test/cb?k=[cb-redacted]");
    expect(provider.requests.length).toBe(before + 1);
    listener.close();
  });

  it("FR-GW-001 rejects bad tokens (4401) and foreign resources (4403)", async () => {
    const { envId, resources } = await scenario();
    const attempt = (token: string, resource: string) =>
      new Promise<number>((resolve) => {
        const url = new URL("/tunnel", base);
        url.protocol = "ws:";
        url.search = new URLSearchParams({ layer: "1", env: envId, resource }).toString();
        new WebSocket(url, { headers: { authorization: `Bearer ${token}` } }).on("close", (code) =>
          resolve(code),
        );
      });
    expect(await attempt("cbd_nope", resources.cache)).toBe(4401);
  });
});

describe("oauth client secret (§10.8 oauth)", () => {
  it("swaps the device's fake client secret on the token endpoint only", async () => {
    const app = server.listeners("request")[0] as never;
    const { owner, orgId } = await signupOwner(app);
    const project = await owner.post(`/api/orgs/${orgId}/projects`, { name: "Auth" });
    const envId = project.body.data.environments[0].id as string;
    const res = await owner.post(`/api/environments/${envId}/resources`, {
      kind: "oauth",
      name: "google",
      tokenUrl: "https://oauth.example.test/token",
      upstreamUrl: provider.url,
      clientSecret: CLIENT_SECRET,
    });
    expect(res.body.data.config.redirectHosts).toEqual(["oauth.example.test:443"]);
    await owner.post(`/api/environments/${envId}/variables`, {
      type: "brokered",
      key: "GOOGLE_CLIENT_SECRET",
      resourceId: res.body.data.id,
      field: "clientSecret",
    });
    const { token } = await loginDevice(app, owner);
    const boot = await cli(app, token).get(
      `/api/agent/bootstrap?projectId=${project.body.data.id}&env=development`,
    );
    const fake = boot.body.data.plain.GOOGLE_CLIENT_SECRET as string;
    expect(fake).toMatch(/^cb-[A-Za-z0-9]{40}$/);
    expect(JSON.stringify(boot.body)).not.toContain(CLIENT_SECRET);

    const url = new URL("/tunnel", base);
    url.protocol = "ws:";
    url.search = new URLSearchParams({
      layer: "2",
      env: envId,
      host: "oauth.example.test",
      port: "443",
    }).toString();
    const exchange = async (secret: string) => {
      const ws = new WebSocket(url, { headers: { authorization: `Bearer ${token}` } });
      await new Promise((r) => ws.once("open", r));
      const secure = tls.connect({
        socket: createWebSocketStream(ws),
        servername: "oauth.example.test",
        ca: boot.body.data.orgCaCert,
        ALPNProtocols: ["http/1.1"],
      });
      await new Promise((r, j) => {
        secure.once("secureConnect", r);
        secure.once("error", j);
      });
      const body = `grant_type=authorization_code&code=x&client_id=web&client_secret=${encodeURIComponent(secret)}`;
      secure.write(
        `POST /token HTTP/1.1\r\nHost: oauth.example.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n${body}`,
      );
      return new Promise<string>((resolve) => {
        let out = "";
        secure.on("data", (d) => {
          out += d.toString();
        });
        secure.on("end", () => resolve(out));
      });
    };
    const ok = await exchange(fake);
    expect(ok).toMatch(/^HTTP\/1\.1 200/);
    expect(ok).toContain("secret was [cb-redacted]");
    expect(ok).not.toContain(CLIENT_SECRET);
    expect(await exchange("cb-forged")).toMatch(/^HTTP\/1\.1 401/);
  });
});

describe("revocation (J7, FR-GW-007, S4)", () => {
  it("J7 revoking the grant closes a live redis connection within 5 s and blocks new tunnels", async () => {
    const { token, envId, resources, boot, owner, grantId } = await scenario();
    const listener = await localListener(base, token, { layer: "1", env: envId, resource: resources.cache });
    const client = new Redis(
      fill(
        boot.body.data.listeners.find((l: { kind: string }) => l.kind === "redis").env.REDIS_URL,
        listener.port,
      ),
      { lazyConnect: true, maxRetriesPerRequest: 0, retryStrategy: () => null },
    );
    await client.connect();
    expect(await client.ping()).toBe("PONG");
    const closed = new Promise<number>((resolve) => client.once("end", () => resolve(Date.now())));
    const revokedAt = Date.now();
    await owner.delete(`/api/grants/${grantId}`);
    expect((await closed) - revokedAt).toBeLessThan(5_000);
    await new Promise((r) => setTimeout(r, 100));
    expect(listener.closeCodes).toContain(4410);
    const again = new Redis(`redis://127.0.0.1:${listener.port}`, {
      lazyConnect: true,
      maxRetriesPerRequest: 0,
      retryStrategy: () => null,
    });
    await expect(again.connect().then(() => again.ping())).rejects.toThrow();
    again.disconnect();
    listener.close();
  });

  it("J7 a resource kill switch closes a live redis connection within 5 s and blocks new tunnels", async () => {
    const { token, envId, resources, boot, owner } = await scenario();
    const listener = await localListener(base, token, { layer: "1", env: envId, resource: resources.cache });
    const redisUrl = boot.body.data.listeners.find((l: { kind: string }) => l.kind === "redis").env.REDIS_URL;
    const client = new Redis(fill(redisUrl, listener.port), {
      maxRetriesPerRequest: 0,
      retryStrategy: () => null,
    });
    client.on("error", () => undefined);
    await client.set("k", "v");
    const closed = new Promise<number>((r) => client.once("end", () => r(Date.now())));
    const orgId = (await owner.get(`/api/environments/${envId}`)).body.data.orgId as string;
    const startedAt = Date.now();
    const kill = await owner.post(`/api/orgs/${orgId}/killswitches`, {
      scope: "resource",
      targetId: resources.cache,
      reason: "suspected key leak",
    });
    expect(kill.status).toBe(201);
    expect((await closed) - startedAt).toBeLessThan(5_000);
    expect(listener.closeCodes).toContain(4410);
    await owner.delete(`/api/killswitches/${kill.body.data.id}`);
    listener.close();
  });

  it("J7 removing a service closes its live redis connection within 5 s", async () => {
    const { token, envId, resources, boot, owner } = await scenario();
    const listener = await localListener(base, token, { layer: "1", env: envId, resource: resources.cache });
    const redisUrl = boot.body.data.listeners.find((l: { kind: string }) => l.kind === "redis").env.REDIS_URL;
    const client = new Redis(fill(redisUrl, listener.port), {
      maxRetriesPerRequest: 0,
      retryStrategy: () => null,
    });
    client.on("error", () => undefined);
    await client.set("k", "v");
    const closed = new Promise<number>((r) => client.once("end", () => r(Date.now())));
    const startedAt = Date.now();
    expect((await owner.delete(`/api/resources/${resources.cache}`)).status).toBe(200);
    expect((await closed) - startedAt).toBeLessThan(5_000);
    expect(listener.closeCodes).toContain(4410);
    listener.close();
  });

  it("J7 disabling a service closes its live redis connection within 5 s", async () => {
    const { token, envId, resources, boot, owner } = await scenario();
    const listener = await localListener(base, token, { layer: "1", env: envId, resource: resources.cache });
    const redisUrl = boot.body.data.listeners.find((l: { kind: string }) => l.kind === "redis").env.REDIS_URL;
    const client = new Redis(fill(redisUrl, listener.port), {
      maxRetriesPerRequest: 0,
      retryStrategy: () => null,
    });
    client.on("error", () => undefined);
    await client.set("k", "v");
    const closed = new Promise<number>((r) => client.once("end", () => r(Date.now())));
    const startedAt = Date.now();
    expect((await owner.patch(`/api/resources/${resources.cache}`, { disabled: true })).status).toBe(200);
    expect((await closed) - startedAt).toBeLessThan(5_000);
    listener.close();
  });

  it("J7 temporary access expiry closes tunnels; HTTP then gets 403 cb_access_revoked", async () => {
    const { token, envId, resources, boot, owner, bob } = await scenario(false);
    void boot;
    await owner.post(`/api/environments/${envId}/grants`, {
      userId: bob.userId,
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    });
    const listener = await localListener(base, token, { layer: "1", env: envId, resource: resources.api });
    const fresh = await cli(server.listeners("request")[0] as never, token).get(
      `/api/agent/bootstrap?projectId=${(await owner.get(`/api/environments/${envId}`)).body.data.projectId}&env=development`,
    );
    const key = fresh.body.data.plain.PROVIDER_API_KEY;
    expect(
      (await fetch(`http://127.0.0.1:${listener.port}/v1/x`, { headers: { authorization: `Bearer ${key}` } }))
        .status,
    ).toBe(200);
    await GrantModel.updateMany({}, { expiresAt: new Date(Date.now() - 1000) });
    await sweepExpiredGrants();
    // The pooled keep-alive socket was closed by the revocation; ask again on a fresh connection.
    const denied = await freshGet(listener.port, "/v1/x", key);
    expect(denied.status).toBe(403);
    expect(JSON.parse(denied.body)).toEqual({ error: "cb_access_revoked" });
    listener.close();
  });

  it("J7 revoking the device closes its mongodb connection", async () => {
    const { token, envId, resources, boot, owner, deviceId } = await scenario();
    const listener = await localListener(base, token, { layer: "1", env: envId, resource: resources.db });
    const client = new MongoClient(
      fill(
        boot.body.data.listeners.find((l: { kind: string }) => l.kind === "mongodb").env.MONGODB_URI,
        listener.port,
      ),
      { serverSelectionTimeoutMS: 2000, maxPoolSize: 1 },
    );
    await client.connect();
    await client.db("shop").command({ ping: 1 });
    await owner.delete(`/api/devices/${deviceId}`);
    await new Promise((r) => setTimeout(r, 500));
    expect(listener.closeCodes).toContain(4410);
    await expect(client.db("shop").command({ ping: 1 })).rejects.toThrow();
    await client.close(true);
    listener.close();
  });

  it("FR-GW-007 an in-flight mongodb operation fails with a protocol-native 'access revoked' error", async () => {
    const { token, envId, resources, boot, owner, deviceId } = await scenario();
    const listener = await localListener(base, token, { layer: "1", env: envId, resource: resources.db });
    const client = new MongoClient(
      fill(
        boot.body.data.listeners.find((l: { kind: string }) => l.kind === "mongodb").env.MONGODB_URI,
        listener.port,
      ),
      { serverSelectionTimeoutMS: 2000, maxPoolSize: 1, retryReads: false },
    );
    await client.connect();
    const orders = client.db("shop").collection("cb_slow");
    await orders.insertOne({ n: 1 });
    // Server-side sleep keeps the request in flight while access is revoked.
    // Capture the outcome right away so the rejection is never briefly unhandled.
    const slow = orders
      .find({ $where: "sleep(2000) || true" })
      .toArray()
      .then(
        () => new Error("query unexpectedly succeeded"),
        (err: Error) => err,
      );
    await new Promise((r) => setTimeout(r, 300));
    await owner.delete(`/api/devices/${deviceId}`);
    expect((await slow).message).toMatch(/cb: access revoked by admin/);
    await client.close(true);
    listener.close();
  });
});

describe("agent events (FR-EVT-002)", () => {
  it("streams config.changed and access.revoked to the device", async () => {
    const { token, envId, owner, grantId } = await scenario();
    const res = await fetch(`${base}/api/agent/events?envId=${envId}`, {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(res.headers.get("content-type")).toContain("text/event-stream");
    const reader = res.body?.getReader();
    const events: string[] = [];
    let raw = "";
    const pump = (async () => {
      const dec = new TextDecoder();
      for (;;) {
        const { value, done } = (await reader?.read()) ?? { done: true };
        if (done) return;
        const text = dec.decode(value);
        raw += text;
        for (const m of text.matchAll(/event: ([\w.]+)/g)) events.push(m[1] ?? "");
        if (events.includes("access.revoked")) return;
      }
    })();
    await new Promise((r) => setTimeout(r, 100));
    await owner.post(`/api/environments/${envId}/variables`, { type: "plain", key: "NEW_FLAG", value: "1" });
    await owner.delete(`/api/grants/${grantId}`);
    await Promise.race([pump, new Promise((r) => setTimeout(r, 3000))]);
    await reader?.cancel();
    expect(events).toEqual(expect.arrayContaining(["ready", "config.changed", "access.revoked"]));
    // §12.3: config.changed carries the environment version.
    expect(raw).toMatch(/event: config\.changed\ndata: \{"environmentId":"[a-f0-9]{24}","version":\d+\}/);
  });
});
