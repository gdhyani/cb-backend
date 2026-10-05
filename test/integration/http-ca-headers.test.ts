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

const KEY = "REAL_INTERNAL_KEY_8812";
let backendDb: Awaited<ReturnType<typeof startMemoryMongo>>;
let provider: https.Server;
let providerUrl: string;
let caPem: string;
let server: http.Server;
let base: string;

beforeAll(async () => {
  backendDb = await startMemoryMongo();
  const ca = await createCa("internal API CA");
  caPem = ca.certPem;
  const leaf = await mintLeaf(ca, "localhost");
  // An internal API on a private CA: only reachable when the service trusts that CA (no test-only CA file here).
  provider = https.createServer({ cert: leaf.certPem, key: leaf.keyPem }, (req, res) => {
    req.resume();
    const ok = req.headers.authorization === `Bearer ${KEY}`;
    res.writeHead(ok ? 200 : 401, { "content-type": "application/json" });
    res.end(
      JSON.stringify({
        ok,
        org: req.headers["openai-organization"] ?? null,
        beta: req.headers["x-beta"] ?? null,
      }),
    );
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
  await mongoose.connection.db?.dropDatabase();
});

describe("OQ9 API services: own CA certificate and extra request headers", () => {
  it("trusts the service's CA (Save & test and the gateway) and adds its headers; the key can't be overridden", async () => {
    const app = server.listeners("request")[0] as never;
    const { owner, orgId } = await signupOwner(app);
    const project = await owner.post(`/api/orgs/${orgId}/projects`, { name: "Shop" });
    const envId = project.body.data.environments[0].id as string;
    const url = `/api/environments/${envId}/services`;
    const untrusted = await owner.post(url, {
      key: "INTERNAL_API_KEY",
      resource: { kind: "http", upstreamUrl: providerUrl, apiKey: KEY, testPath: "/v1/models" },
    });
    expect(untrusted.status).toBe(422); // private CA, not trusted
    const badHeader = await owner.post(url, {
      key: "INTERNAL_API_KEY",
      test: false,
      resource: {
        kind: "http",
        upstreamUrl: providerUrl,
        apiKey: KEY,
        extraHeaders: { Authorization: "Bearer x" },
      },
    });
    expect(badHeader.status).toBe(400);
    const created = await owner.post(url, {
      key: "INTERNAL_API_KEY",
      resource: {
        kind: "http",
        upstreamUrl: providerUrl,
        apiKey: KEY,
        testPath: "/v1/models",
        caCert: caPem,
        extraHeaders: { "OpenAI-Organization": "org_123", "x-beta": "assistants=v2" },
      },
    });
    expect(created.status, JSON.stringify(created.body)).toBe(201);
    expect(created.body.data.service.config).toMatchObject({
      extraHeaders: { "openai-organization": "org_123", "x-beta": "assistants=v2" },
    });

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
    const res = await fetch(`http://127.0.0.1:${listener.port}/v1/models`, {
      headers: { authorization: `Bearer ${boot.body.data.plain.INTERNAL_API_KEY}`, "x-beta": "app-value" },
    });
    expect(await res.json()).toEqual({ ok: true, org: "org_123", beta: "assistants=v2" });
    listener.close();
  });
});
