import http from "node:http";
import type { AddressInfo } from "node:net";
import mongoose from "mongoose";
import { afterAll, beforeAll, beforeEach, expect, it } from "vitest";
import { createApp } from "../../src/app.js";
import { connectMongo, disconnectMongo } from "../../src/clients/mongodb.client.js";
import { loadEnv, setEnv } from "../../src/config/env.js";
import { createServer } from "../../src/server.js";
import { localListener } from "../helpers/agent.js";
import { cli, loginDevice, signupOwner } from "../helpers/api.js";
import { testEnvVars } from "../helpers/env.js";
import { startMemoryMongo } from "../helpers/mongo.js";

const REAL = "REAL_GEMINI_KEY_5521";
let db: Awaited<ReturnType<typeof startMemoryMongo>>;
let server: http.Server;
let base: string;
let model: http.Server;
let modelUrl: string;
const seen: (string | undefined)[] = [];

beforeAll(async () => {
  db = await startMemoryMongo();
  setEnv(loadEnv(testEnvVars(db.uri)));
  await connectMongo(db.uri);
  server = createServer(createApp()).server;
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  // A self-hosted, plain-http "model server" on a private address that wants the key in x-goog-api-key.
  model = http.createServer((req, res) => {
    seen.push(req.headers["x-goog-api-key"] as string | undefined);
    const ok = req.headers["x-goog-api-key"] === REAL;
    res.writeHead(ok ? 200 : 401, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok, path: req.url }));
  });
  await new Promise<void>((r) => model.listen(0, "127.0.0.1", r));
  modelUrl = `http://127.0.0.1:${(model.address() as AddressInfo).port}`;
}, 60_000);
afterAll(async () => {
  server.closeAllConnections();
  server.close();
  model.close();
  await disconnectMongo();
  await db.stop();
});
beforeEach(async () => {
  await mongoose.connection.db?.dropDatabase();
});

it("D12 named-header key: fake verified and swapped in x-goog-api-key over a private http upstream (D11)", async () => {
  const app = server.listeners("request")[0] as never;
  const { owner, orgId } = await signupOwner(app);
  const project = await owner.post(`/api/orgs/${orgId}/projects`, { name: "AI" });
  const envId = project.body.data.environments[0].id as string;
  const llm = await owner.post(`/api/environments/${envId}/resources`, {
    kind: "http",
    name: "llm",
    upstreamUrl: modelUrl,
    authScheme: "header",
    authHeader: "x-goog-api-key",
    provider: "ai-custom",
    apiKey: REAL,
  });
  expect(llm.status).toBe(201);
  expect(llm.body.data.config).toMatchObject({
    authScheme: "header",
    authHeader: "x-goog-api-key",
    provider: "ai-custom",
  });
  for (const v of [
    { type: "brokered", key: "LLM_API_KEY", resourceId: llm.body.data.id, field: "key" },
    { type: "brokered", key: "LLM_BASE_URL", resourceId: llm.body.data.id, field: "baseUrl" },
  ])
    expect((await owner.post(`/api/environments/${envId}/variables`, v)).status).toBe(201);
  const test = await owner.post(`/api/resources/${llm.body.data.id}/test`, {});
  expect(test.body.data.ok).toBe(true);
  const { token } = await loginDevice(app, owner);
  const boot = await cli(app, token).get(
    `/api/agent/bootstrap?projectId=${project.body.data.id}&env=development`,
  );
  const fake = boot.body.data.plain.LLM_API_KEY as string;
  expect(fake).toBeTruthy();
  expect(fake).not.toContain(REAL);
  const listener = await localListener(base, token, { layer: "1", env: envId, resource: llm.body.data.id });
  const res = await fetch(`http://127.0.0.1:${listener.port}/v1/models`, {
    headers: { "x-goog-api-key": fake },
  });
  expect(res.status).toBe(200);
  expect(seen.at(-1)).toBe(REAL);
  const bad = await fetch(`http://127.0.0.1:${listener.port}/v1/models`, {
    headers: { "x-goog-api-key": "forged" },
  });
  expect(bad.status).toBe(401);
  listener.close();
});

it("D12 authHeader is required with the header scheme and must be a lowercase header token", async () => {
  const app = server.listeners("request")[0] as never;
  const { owner, orgId } = await signupOwner(app, "2");
  const project = await owner.post(`/api/orgs/${orgId}/projects`, { name: "AI" });
  const envId = project.body.data.environments[0].id as string;
  const body = {
    kind: "http",
    name: "x",
    upstreamUrl: "https://api.example.com",
    authScheme: "header",
    apiKey: "k",
  };
  expect((await owner.post(`/api/environments/${envId}/resources`, body)).status).toBe(400);
  expect(
    (await owner.post(`/api/environments/${envId}/resources`, { ...body, authHeader: "X Bad" })).status,
  ).toBe(400);
});
