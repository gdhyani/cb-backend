import type http from "node:http";
import type { AddressInfo } from "node:net";
import { MongoClient } from "mongodb";
import { MongoMemoryReplSet } from "mongodb-memory-server";
import mongoose from "mongoose";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createApp } from "../../src/app.js";
import { connectMongo, disconnectMongo } from "../../src/clients/mongodb.client.js";
import { loadEnv, setEnv } from "../../src/config/env.js";
import { createServer } from "../../src/server.js";
import { localListener } from "../helpers/agent.js";
import { addMember, cli, loginDevice, signupOwner } from "../helpers/api.js";
import { testEnvVars } from "../helpers/env.js";
import { startMemoryMongo } from "../helpers/mongo.js";

const PW = "REAL_REPLSET_PW_6203";
let backendDb: Awaited<ReturnType<typeof startMemoryMongo>>;
let rs: MongoMemoryReplSet;
let server: http.Server;
let base: string;

beforeAll(async () => {
  [backendDb, rs] = await Promise.all([
    startMemoryMongo(),
    MongoMemoryReplSet.create({
      replSet: {
        count: 2,
        storageEngine: "wiredTiger",
        auth: { enable: true, customRootName: "root", customRootPwd: PW },
      },
    }),
  ]);
  await rs.waitUntilRunning();
  setEnv(loadEnv(testEnvVars(backendDb.uri)));
  await connectMongo(backendDb.uri);
  server = createServer(createApp()).server;
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}, 180_000);
afterAll(async () => {
  server.closeAllConnections();
  server.close();
  await disconnectMongo();
  await Promise.all([backendDb.stop(), rs.stop()]);
});
beforeEach(async () => {
  await mongoose.connection.db?.dropDatabase();
});

/** host:port of every member, secondaries first, so the gateway has to discover the primary itself. */
async function membersSecondaryFirst(): Promise<string[]> {
  const admin = new MongoClient(
    rs.getUri().replace("mongodb://", `mongodb://root:${PW}@`).replace("?", "?authSource=admin&"),
  );
  await admin.connect();
  const status = await admin.db("admin").command({ replSetGetStatus: 1 });
  await admin.close();
  const members = status.members as { name: string; stateStr: string }[];
  return [...members]
    .sort((a, b) => (a.stateStr === "PRIMARY" ? 1 : 0) - (b.stateStr === "PRIMARY" ? 1 : 0))
    .map((m) => m.name);
}

describe("MongoDB replica sets through the gateway (§10.8: primary discovery)", () => {
  it("T4 a multi-host URI listing the secondary first still writes: the gateway connects to the primary", async () => {
    const app = server.listeners("request")[0] as never;
    const { owner, orgId } = await signupOwner(app);
    const project = await owner.post(`/api/orgs/${orgId}/projects`, { name: "Shop" });
    const envId = project.body.data.environments[0].id as string;
    const hosts = (await membersSecondaryFirst()).join(",");
    const r = await owner.post(`/api/environments/${envId}/resources`, {
      kind: "mongodb",
      name: "replset",
      connectionUri: `mongodb://root:${PW}@${hosts}/shop?authSource=admin&replicaSet=${rs.replSetOpts.name}`,
    });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    await owner.post(`/api/environments/${envId}/variables`, {
      type: "brokered",
      key: "MONGODB_URI",
      resourceId: r.body.data.id,
      field: "url",
    });
    const bob = await addMember(app, owner, orgId, "Bob");
    await owner.post(`/api/environments/${envId}/grants`, { userId: bob.userId });
    const { token } = await loginDevice(app, bob.member);
    const boot = await cli(app, token).get(
      `/api/agent/bootstrap?projectId=${project.body.data.id}&env=development`,
    );
    const url = boot.body.data.listeners.find((l: { kind: string }) => l.kind === "mongodb").env
      .MONGODB_URI as string;
    const listener = await localListener(base, token, { layer: "1", env: envId, resource: r.body.data.id });
    const client = new MongoClient(url.replace("{port}", String(listener.port)), {
      serverSelectionTimeoutMS: 8000,
    });
    await client.connect();
    const coll = client.db("shop").collection("orders");
    await coll.insertOne({ sku: "RS1" }); // writes fail on a secondary (NotWritablePrimary)
    expect(await coll.findOne({ sku: "RS1" })).toMatchObject({ sku: "RS1" });
    await client.close();
    listener.close();
  });
});
