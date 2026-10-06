import type http from "node:http";
import https from "node:https";
import type { AddressInfo } from "node:net";
import mongoose from "mongoose";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createApp } from "../../src/app.js";
import { connectMongo, disconnectMongo } from "../../src/clients/mongodb.client.js";
import { loadEnv, setEnv } from "../../src/config/env.js";
import { createCa, mintLeaf } from "../../src/crypto/ca.js";
import { resetUpstreamDispatcher } from "../../src/gateway/http/upstream.js";
import { createServer } from "../../src/server.js";
import { localListener } from "../helpers/agent.js";
import { addMember, cli, loginDevice, signupOwner } from "../helpers/api.js";
import { testEnvVars } from "../helpers/env.js";
import { startMemoryMongo } from "../helpers/mongo.js";

const SECRET = "sb_secret_REAL_SUPABASE_KEY_4417";
const PUBLISHABLE = "sb_publishable_PUBLIC_KEY_0001";
let backendDb: Awaited<ReturnType<typeof startMemoryMongo>>;
let provider: https.Server;
let providerUrl: string;
let caPem: string;
let server: http.Server;
let base: string;
/** Every request the Supabase stand-in saw: apikey + authorization as received. */
const seen: { apikey?: string; authorization?: string; other?: string }[] = [];

beforeAll(async () => {
  backendDb = await startMemoryMongo();
  const ca = await createCa("supabase stand-in CA");
  caPem = ca.certPem;
  const leaf = await mintLeaf(ca, "localhost");
  // Like Supabase: the secret key in `apikey` must match `Authorization: Bearer` when that is sent too; the
  // publishable key is a public key that works on its own.
  provider = https.createServer({ cert: leaf.certPem, key: leaf.keyPem }, (req, res) => {
    req.resume();
    const apikey = req.headers.apikey as string | undefined;
    const authorization = req.headers.authorization;
    seen.push({ apikey, authorization, other: req.headers["x-forward-key"] as string | undefined });
    const secretOk = apikey === SECRET && (!authorization || authorization === `Bearer ${SECRET}`);
    const publicOk = apikey === PUBLISHABLE;
    res.writeHead(secretOk || publicOk ? 200 : 401, { "content-type": "application/json" });
    res.end(JSON.stringify({ role: secretOk ? "service" : publicOk ? "anon" : "none" }));
  });
  await new Promise<void>((r) => provider.listen(0, "127.0.0.1", r));
  providerUrl = `https://localhost:${(provider.address() as AddressInfo).port}`;
  setEnv(loadEnv(testEnvVars(backendDb.uri)));
  resetUpstreamDispatcher();
  await connectMongo(backendDb.uri);
  server = createServer(createApp()).server;
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}, 120_000);
afterAll(async () => {
  server.closeAllConnections();
  server.close();
  provider.close();
  await disconnectMongo();
  await backendDb.stop();
});
beforeEach(async () => {
  seen.length = 0;
  await mongoose.connection.db?.dropDatabase();
});

async function setup(resource: Record<string, unknown>, preset?: string) {
  const app = server.listeners("request")[0] as never;
  const { owner, orgId } = await signupOwner(app);
  const project = await owner.post(`/api/orgs/${orgId}/projects`, { name: "Shop" });
  const envId = project.body.data.environments[0].id as string;
  const created = await owner.post(`/api/environments/${envId}/services`, {
    key: "SUPABASE_SECRET_KEY",
    ...(preset ? { preset } : {}),
    resource: { kind: "http", upstreamUrl: providerUrl, apiKey: SECRET, caCert: caPem, ...resource },
  });
  expect(created.status, JSON.stringify(created.body)).toBe(201);
  const bob = await addMember(app, owner, orgId, "Bob");
  await owner.post(`/api/environments/${envId}/grants`, { userId: bob.userId });
  const { token } = await loginDevice(app, bob.member);
  const boot = await cli(app, token).get(
    `/api/agent/bootstrap?projectId=${project.body.data.id}&env=development`,
  );
  const listener = await localListener(base, token, {
    layer: "1",
    env: envId,
    resource: created.body.data.service.id,
  });
  seen.length = 0; // Save & test called the provider; only the app's calls count from here
  const call = (headers: Record<string, string>) =>
    fetch(`http://127.0.0.1:${listener.port}/rest/v1/`, { headers }).then(async (r) => ({
      status: r.status,
      body: await r.json(),
    }));
  return {
    fake: boot.body.data.plain.SUPABASE_SECRET_KEY as string,
    call,
    close: () => listener.close(),
    created,
  };
}

describe("FR-GW-005 SDKs that send the key in two headers (Supabase: apikey + Authorization)", () => {
  it("the Supabase preset swaps the device's fake in every header that carries it; the app sees only the fake", async () => {
    const s = await setup({}, "supabase");
    expect(s.fake).toMatch(/^sb_secret_cb_/);
    expect(s.created.body.data.service.config).toMatchObject({
      authScheme: "header",
      authHeader: "apikey",
      passOtherKeys: true,
    });
    const r = await s.call({
      apikey: s.fake,
      authorization: `Bearer ${s.fake}`,
      "x-forward-key": `key=${s.fake}`,
    });
    expect(r).toEqual({ status: 200, body: { role: "service" } });
    expect(seen.at(-1)).toEqual({
      apikey: SECRET,
      authorization: `Bearer ${SECRET}`,
      other: `key=${SECRET}`,
    });
    s.close();
  });

  it("the public publishable key passes through unchanged: no real secret is added to it", async () => {
    const s = await setup({}, "supabase");
    const r = await s.call({ apikey: PUBLISHABLE, authorization: `Bearer ${PUBLISHABLE}` });
    expect(r).toEqual({ status: 200, body: { role: "anon" } });
    expect(seen.at(-1)).toEqual({ apikey: PUBLISHABLE, authorization: `Bearer ${PUBLISHABLE}` });
    // No key at all: also passed through as it is (public endpoints), never with the secret.
    await s.call({});
    expect(seen.at(-1)?.apikey).toBeUndefined();
    expect(JSON.stringify(seen)).not.toContain(SECRET);
    s.close();
  });

  it("a stand-in that is not this device's is still refused, even where other keys may pass", async () => {
    const s = await setup({}, "supabase");
    const r = await s.call({ apikey: `sb_secret_cb_${"x".repeat(40)}` });
    expect(r.status).toBe(401);
    expect(r.body).toEqual({ error: "cb_invalid_credential" });
    expect(seen).toHaveLength(0);
    s.close();
  });

  it("without passOtherKeys an unknown key is refused as before", async () => {
    const s = await setup({
      authScheme: "header",
      authHeader: "apikey",
      fakePrefix: "sb_secret_cb_",
      testPath: "/rest/v1/",
    });
    const r = await s.call({ apikey: PUBLISHABLE });
    expect(r.status).toBe(401);
    expect(seen).toHaveLength(0);
    s.close();
  });
});
