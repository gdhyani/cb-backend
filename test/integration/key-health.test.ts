import type http from "node:http";
import type { AddressInfo } from "node:net";
import { Redis } from "ioredis";
import mongoose from "mongoose";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createApp } from "../../src/app.js";
import { connectMongo, disconnectMongo } from "../../src/clients/mongodb.client.js";
import { loadEnv, setEnv } from "../../src/config/env.js";
import { resetUpstreamDispatcher } from "../../src/gateway/http/upstream.js";
import { createServer } from "../../src/server.js";
import { resetHealthThrottle } from "../../src/services/resource-health.service.js";
import { localListener } from "../helpers/agent.js";
import { addMember, cli, loginDevice, signupOwner } from "../helpers/api.js";
import { testEnvVars } from "../helpers/env.js";
import { startMockProvider } from "../helpers/mock-provider.js";
import { startMemoryMongo } from "../helpers/mongo.js";
import { startRedis } from "../helpers/redis-server.js";

const GOOD = "REAL_HEALTH_GOOD_KEY_01";
const DELETED = "REAL_HEALTH_DELETED_KEY_02";
const REDIS_PW = "REAL_HEALTH_REDIS_PW_03";
let backendDb: Awaited<ReturnType<typeof startMemoryMongo>>;
let provider: Awaited<ReturnType<typeof startMockProvider>>;
let redis: Awaited<ReturnType<typeof startRedis>>;
let server: http.Server;
let base: string;

beforeAll(async () => {
  [backendDb, provider, redis] = await Promise.all([
    startMemoryMongo(),
    startMockProvider(GOOD),
    startRedis(REDIS_PW),
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
  await backendDb.stop();
  provider.close();
  redis.stop();
});
beforeEach(async () => {
  resetHealthThrottle();
  await mongoose.connection.db?.dropDatabase();
});

async function setup(resource: Record<string, unknown>, field: string) {
  const app = server.listeners("request")[0] as never;
  const { owner, orgId } = await signupOwner(app);
  const project = await owner.post(`/api/orgs/${orgId}/projects`, { name: "Shop" });
  const envId = project.body.data.environments[0].id as string;
  const created = await owner.post(`/api/environments/${envId}/services`, {
    key: "THE_KEY",
    mainField: field,
    test: false,
    resource,
  });
  if (created.status !== 201) throw new Error(JSON.stringify(created.body));
  const id = created.body.data.service.id as string;
  const bob = await addMember(app, owner, orgId, "Bob");
  await owner.post(`/api/environments/${envId}/grants`, { userId: bob.userId });
  const { token } = await loginDevice(app, bob.member);
  const boot = await cli(app, token).get(
    `/api/agent/bootstrap?projectId=${project.body.data.id}&env=development`,
  );
  const health = async () => {
    const list = await owner.get(`/api/environments/${envId}/resources`);
    return (list.body.data as { id: string; health: { status: string; reason?: string } }[]).find(
      (r) => r.id === id,
    )?.health;
  };
  return { owner, envId, id, token, boot, health };
}

const until = async (fn: () => Promise<unknown>, want: string) => {
  for (let i = 0; i < 40; i++) {
    const h = (await fn()) as { status?: string } | undefined;
    if (h?.status === want) return h;
    await new Promise((r) => setTimeout(r, 50));
  }
  return fn();
};

describe("key health (B11): green when the provider accepts the key, Expired when it rejects it", () => {
  it("a new key saved without a test is 'unknown'", async () => {
    const { health } = await setup({ kind: "http", upstreamUrl: provider.url, apiKey: GOOD }, "key");
    expect(await health()).toMatchObject({ status: "unknown" });
  });

  it("a key the provider no longer accepts turns 'rejected' on the next call; Replace value makes it 'ok' again", async () => {
    const { owner, envId, id, token, boot, health } = await setup(
      { kind: "http", upstreamUrl: provider.url, apiKey: DELETED, testPath: "/v1/models" },
      "key",
    );
    const listener = await localListener(base, token, { layer: "1", env: envId, resource: id });
    const res = await fetch(`http://127.0.0.1:${listener.port}/v1/models`, {
      headers: { authorization: `Bearer ${boot.body.data.plain.THE_KEY}` },
    });
    expect(res.status).toBe(401); // the app still gets the provider's own answer
    await res.text();
    const rejected = await until(health, "rejected");
    expect(rejected).toMatchObject({ status: "rejected", reason: expect.stringMatching(/Replace value/) });
    expect(JSON.stringify(rejected)).not.toContain(DELETED);

    expect((await owner.patch(`/api/resources/${id}`, { apiKey: GOOD, test: true })).status).toBe(200);
    expect(await until(health, "ok")).toMatchObject({ status: "ok" });
    listener.close();
  });

  it("I2 a pass-through request (not the stored key) never changes the key's status", async () => {
    const { envId, id, token, health } = await setup(
      { kind: "http", upstreamUrl: provider.url, apiKey: GOOD, passOtherKeys: true, fakePrefix: "sk_cb_" },
      "key",
    );
    const listener = await localListener(base, token, { layer: "1", env: envId, resource: id });
    // A user's own (public / expired) token passes through untouched; the provider refuses it with 401.
    const res = await fetch(`http://127.0.0.1:${listener.port}/v1/models`, {
      headers: { authorization: "Bearer user-jwt-expired" },
    });
    expect(res.status).toBe(401);
    await res.text();
    await new Promise((r) => setTimeout(r, 300));
    expect(await health()).toMatchObject({ status: "unknown" });
    listener.close();
  });

  it("Test connection records the result", async () => {
    const { owner, id, health } = await setup(
      { kind: "http", upstreamUrl: provider.url, apiKey: DELETED, testPath: "/v1/models" },
      "key",
    );
    await owner.post(`/api/resources/${id}/test`, {});
    expect(await until(health, "rejected")).toMatchObject({ status: "rejected" });
  });

  it("a database whose stored password stopped working turns 'rejected' when an app connects", async () => {
    const { envId, id, token, boot, health } = await setup(
      { kind: "redis", connectionUri: redis.uri.replace(REDIS_PW, "REAL_HEALTH_OLD_PW_04") },
      "url",
    );
    const listener = await localListener(base, token, { layer: "1", env: envId, resource: id });
    const url = (boot.body.data.listeners as { env: Record<string, string> }[])[0]?.env.THE_KEY ?? "";
    const client = new Redis(url.replace("{port}", String(listener.port)), {
      lazyConnect: true,
      maxRetriesPerRequest: 0,
      retryStrategy: () => null,
    });
    await client.connect().catch(() => undefined);
    await client.ping().catch(() => undefined);
    client.disconnect();
    expect(await until(health, "rejected")).toMatchObject({ status: "rejected" });
    listener.close();
  });
});
