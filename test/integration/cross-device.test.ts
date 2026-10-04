import type http from "node:http";
import { request as httpRequest } from "node:http";
import net, { type AddressInfo } from "node:net";
import { Redis } from "ioredis";
import { MongoClient } from "mongodb";
import { MongoMemoryServer } from "mongodb-memory-server";
import mongoose from "mongoose";
import mysql from "mysql2/promise";
import pg from "pg";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createApp } from "../../src/app.js";
import { connectMongo, disconnectMongo } from "../../src/clients/mongodb.client.js";
import { loadEnv, setEnv } from "../../src/config/env.js";
import { resetUpstreamDispatcher } from "../../src/gateway/http/upstream.js";
import { createServer } from "../../src/server.js";
import { localListener } from "../helpers/agent.js";
import { addMember, cli, loginDevice, signupOwner } from "../helpers/api.js";
import { testEnvVars } from "../helpers/env.js";
import { startMockProvider } from "../helpers/mock-provider.js";
import { startMemoryMongo } from "../helpers/mongo.js";
import { startRedis } from "../helpers/redis-server.js";

const MONGO_PW = "REAL_MONGO_PW_S7_5521";
const REDIS_PW = "REAL_REDIS_PW_S7_8812";
const API_KEY = "REAL_API_KEY_S7_sk_live_31";
// Postgres/MySQL from docker-compose.test.yml; the password is supplied at run time, never stored in files.
const SQL_PW = process.env.CB_TEST_DB_PASSWORD;
const enc = encodeURIComponent(SQL_PW ?? "");

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
    startMockProvider(API_KEY),
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

type Boot = { listeners: { kind: string; env: Record<string, string> }[]; plain: Record<string, string> };

/** One developer, two devices, both allowed; device A's bootstrap gives the fakes that device B will present. */
async function twoDevices() {
  const app = server.listeners("request")[0] as never;
  const { owner, orgId } = await signupOwner(app);
  const project = await owner.post(`/api/orgs/${orgId}/projects`, { name: "Shop" });
  const envId = project.body.data.environments[0].id as string;
  const make = async (body: Record<string, unknown>, vars: [string, string][]) => {
    const r = await owner.post(`/api/environments/${envId}/resources`, body);
    if (r.status !== 201) throw new Error(JSON.stringify(r.body));
    for (const [key, field] of vars)
      await owner.post(`/api/environments/${envId}/variables`, {
        type: "brokered",
        key,
        resourceId: r.body.data.id,
        field,
      });
    return r.body.data.id as string;
  };
  const mongoUri = upstreamMongo
    .getUri()
    .replace("mongodb://", `mongodb://root:${MONGO_PW}@`)
    .replace(/\/?$/, "/shop?authSource=admin");
  const resources: Record<string, string> = {
    db: await make({ kind: "mongodb", name: "main-db", connectionUri: mongoUri }, [["MONGODB_URI", "url"]]),
    cache: await make({ kind: "redis", name: "cache", connectionUri: redis.uri }, [["REDIS_URL", "url"]]),
    api: await make(
      { kind: "http", name: "provider", upstreamUrl: provider.url, apiKey: API_KEY, fakePrefix: "sk_cb_" },
      [["PROVIDER_API_KEY", "key"]],
    ),
  };
  if (SQL_PW) {
    resources.pg = await make(
      {
        kind: "postgres",
        name: "orders-db",
        connectionUri: `postgresql://shop_admin:${enc}@127.0.0.1:5433/shop`,
      },
      [["DATABASE_URL", "url"]],
    );
    resources.mysql = await make(
      { kind: "mysql", name: "legacy-db", connectionUri: `mysql://shop_admin:${enc}@127.0.0.1:3307/shop` },
      [["MYSQL_URL", "url"]],
    );
  }
  const bob = await addMember(app, owner, orgId, "Bob");
  await owner.post(`/api/environments/${envId}/grants`, { userId: bob.userId });
  const a = await loginDevice(app, bob.member, "laptop-a");
  const b = await loginDevice(app, bob.member, "laptop-b");
  const boot = await cli(app, a.token).get(
    `/api/agent/bootstrap?projectId=${project.body.data.id}&env=development`,
  );
  if (boot.status !== 200) throw new Error(JSON.stringify(boot.body));
  return { envId, resources, tokenB: b.token, boot: boot.body.data as Boot };
}

const fakeOf = (boot: Boot, kind: string, port: number) =>
  (Object.values(boot.listeners.find((l) => l.kind === kind)?.env ?? {})[0] ?? "").replace(
    "{port}",
    String(port),
  );

describe("S7 a fake value from device A fails through device B's tunnel", () => {
  it("S7 redis: device A's fake password gets WRONGPASS on device B", async () => {
    const { tokenB, envId, resources, boot } = await twoDevices();
    const l = await localListener(base, tokenB, { layer: "1", env: envId, resource: resources.cache });
    const client = new Redis(fakeOf(boot, "redis", l.port), {
      lazyConnect: true,
      maxRetriesPerRequest: 0,
      retryStrategy: () => null,
    });
    // ioredis reports the server's AUTH reply on "error"; connect() itself rejects with a generic close.
    const authError = new Promise<string>((resolve) => client.on("error", (e: Error) => resolve(e.message)));
    await client.connect().catch(() => undefined);
    expect(await authError).toMatch(/WRONGPASS/);
    client.disconnect();
    l.close();
  });

  it("S7 mongodb: device A's fake SCRAM credential gets AuthenticationFailed (18) on device B", async () => {
    const { tokenB, envId, resources, boot } = await twoDevices();
    const l = await localListener(base, tokenB, { layer: "1", env: envId, resource: resources.db });
    const client = new MongoClient(fakeOf(boot, "mongodb", l.port), { serverSelectionTimeoutMS: 3000 });
    await expect(client.connect()).rejects.toMatchObject({ code: 18 });
    await client.close();
    l.close();
  });

  it("S7 http: device A's fake API key is refused on device B and never reaches the provider", async () => {
    const { tokenB, envId, resources, boot } = await twoDevices();
    const l = await localListener(base, tokenB, { layer: "1", env: envId, resource: resources.api });
    const before = provider.requests.length;
    const fake = boot.plain.PROVIDER_API_KEY ?? "";
    const status = await new Promise<number>((resolve, reject) => {
      const req = httpRequest(
        {
          host: "127.0.0.1",
          port: l.port,
          path: "/echo",
          agent: false,
          headers: { authorization: `Bearer ${fake}` },
        },
        (res) => {
          res.resume();
          resolve(res.statusCode ?? 0);
        },
      );
      req.on("error", reject);
      req.end();
    });
    expect(status).toBe(401);
    expect(provider.requests.length).toBe(before);
    l.close();
  });

  it.skipIf(!SQL_PW)("S7 postgres: device A's fake gets 28P01 on device B", async () => {
    const { tokenB, envId, resources, boot } = await twoDevices();
    const l = await localListener(base, tokenB, { layer: "1", env: envId, resource: resources.pg ?? "" });
    const client = new pg.Client({ connectionString: fakeOf(boot, "postgres", l.port) });
    client.on("error", () => {});
    await expect(client.connect()).rejects.toMatchObject({ code: "28P01" });
    l.close();
  });

  it.skipIf(!SQL_PW)("S7 mysql: device A's fake gets ER_ACCESS_DENIED (1045) on device B", async () => {
    const { tokenB, envId, resources, boot } = await twoDevices();
    const l = await localListener(base, tokenB, { layer: "1", env: envId, resource: resources.mysql ?? "" });
    await expect(mysql.createConnection(fakeOf(boot, "mysql", l.port))).rejects.toMatchObject({
      errno: 1045,
    });
    l.close();
  });
});

describe("FR-GW-001 hostile local input: malformed bytes close one tunnel, never the gateway", () => {
  const garbage = [
    Buffer.alloc(16),
    Buffer.from([0xff, 0xff, 0xff, 0x7f, 0, 0, 0, 0, 0, 0, 0, 0, 0xd5, 0x07, 0, 0]),
    Buffer.from("\x00\x00\x00\x08\x04\xd2\x16\x2f garbage \r\n*-1\r\n$-5\r\n"),
    Buffer.from(Array.from({ length: 64 }, (_, i) => (i * 37) % 256)),
  ];
  const kinds = ["db", "cache", "pg", "mysql"] as const;
  it.each(kinds)("FR-GW-001 %s adapter survives malformed client bytes", async (kind) => {
    if ((kind === "pg" || kind === "mysql") && !SQL_PW) return;
    const { tokenB, envId, resources } = await twoDevices();
    // An authorized tunnel: the bytes reach the adapter before any protocol-level authentication.
    // A throw in an adapter's stream handler would be an uncaught exception (vitest fails the run on it).
    const l = await localListener(base, tokenB, { layer: "1", env: envId, resource: resources[kind] ?? "" });
    for (const bytes of garbage) {
      await new Promise<void>((resolve) => {
        const s = net.connect(l.port, "127.0.0.1", () => s.end(bytes));
        s.on("error", () => resolve());
        s.on("close", () => resolve());
        s.resume();
        setTimeout(() => {
          s.destroy();
          resolve();
        }, 1500);
      });
    }
    await new Promise((r) => setTimeout(r, 300));
    expect(server.listening).toBe(true);
    const health = await fetch(`${base}/api/health`).then(
      (r) => r.status,
      () => 0,
    );
    expect(health).toBe(200);
    l.close();
  });
});
