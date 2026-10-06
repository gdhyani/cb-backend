import type http from "node:http";
import type { AddressInfo } from "node:net";
import mongoose from "mongoose";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createApp } from "../../src/app.js";
import { connectMongo, disconnectMongo } from "../../src/clients/mongodb.client.js";
import { loadEnv, setEnv } from "../../src/config/env.js";
import { resetUpstreamDispatcher } from "../../src/gateway/http/upstream.js";
import { createServer } from "../../src/server.js";
import { addMember, signupOwner } from "../helpers/api.js";
import { testEnvVars } from "../helpers/env.js";
import { startMockProvider } from "../helpers/mock-provider.js";
import { startMemoryMongo } from "../helpers/mongo.js";

const SECRET = "REAL_RBAC_KEY_sk_live_7781";
let backendDb: Awaited<ReturnType<typeof startMemoryMongo>>;
let provider: Awaited<ReturnType<typeof startMockProvider>>;
let server: http.Server;

beforeAll(async () => {
  [backendDb, provider] = await Promise.all([startMemoryMongo(), startMockProvider(SECRET)]);
  setEnv(loadEnv({ ...testEnvVars(backendDb.uri), UPSTREAM_EXTRA_CA_FILE: provider.caFile }));
  resetUpstreamDispatcher();
  await connectMongo(backendDb.uri);
  server = createServer(createApp()).server;
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  void (server.address() as AddressInfo).port;
}, 120_000);
afterAll(async () => {
  server.closeAllConnections();
  server.close();
  await disconnectMongo();
  await backendDb.stop();
  provider.close();
});
beforeEach(async () => {
  await mongoose.connection.db?.dropDatabase();
});

/** Org A (owner + developer with a grant) holding one service, variable and grant; org B's owner is an outsider. */
async function world() {
  const app = server.listeners("request")[0] as never;
  const a = await signupOwner(app);
  const project = await a.owner.post(`/api/orgs/${a.orgId}/projects`, { name: "Shop" });
  const projectId = project.body.data.id as string;
  const envId = project.body.data.environments[0].id as string;
  const res = await a.owner.post(`/api/environments/${envId}/resources`, {
    kind: "http",
    name: "api",
    upstreamUrl: provider.url,
    apiKey: SECRET,
    fakePrefix: "sk_cb_",
  });
  const resourceId = res.body.data.id as string;
  const variable = await a.owner.post(`/api/environments/${envId}/variables`, {
    type: "brokered",
    key: "API_KEY",
    resourceId,
    field: "key",
  });
  const dev = await addMember(app, a.owner, a.orgId, "Dev");
  const other = await addMember(app, a.owner, a.orgId, "Other");
  const grant = await a.owner.post(`/api/environments/${envId}/grants`, { userId: dev.userId });
  const b = await signupOwner(app, "-b");
  return {
    dev: dev.member,
    outsider: b.owner,
    ids: {
      orgId: a.orgId,
      projectId,
      envId,
      resourceId,
      variableId: variable.body.data.id as string,
      grantId: grant.body.data.id as string,
      devId: dev.userId,
      otherId: other.userId,
    },
  };
}

type Ids = Awaited<ReturnType<typeof world>>["ids"];
type Method = "get" | "post" | "patch" | "put" | "delete";

const adminWrites = (i: Ids): [Method, string, Record<string, unknown>?][] => [
  [
    "post",
    `/api/environments/${i.envId}/services`,
    { key: "X_KEY", resource: { kind: "http", upstreamUrl: provider.url, apiKey: "x" } },
  ],
  [
    "post",
    `/api/environments/${i.envId}/resources`,
    { kind: "http", name: "n", upstreamUrl: provider.url, apiKey: "x" },
  ],
  ["post", `/api/environments/${i.envId}/variables`, { type: "plain", key: "P", value: "1" }],
  ["post", `/api/environments/${i.envId}/grants`, { userId: i.devId }],
  ["patch", `/api/environments/${i.envId}`, { name: "renamed" }],
  ["delete", `/api/environments/${i.envId}`],
  ["patch", `/api/resources/${i.resourceId}`, { name: "renamed" }],
  ["delete", `/api/resources/${i.resourceId}`],
  ["post", `/api/resources/${i.resourceId}/test`, {}],
  ["post", `/api/resources/${i.resourceId}/profiles`, { name: "ro", apiKey: "x" }],
  ["post", `/api/resources/${i.resourceId}/webhook/connect`, {}],
  ["patch", `/api/variables/${i.variableId}`, { key: "RENAMED" }],
  ["delete", `/api/variables/${i.variableId}`],
  ["patch", `/api/grants/${i.grantId}`, { expiresAt: null }],
  ["delete", `/api/grants/${i.grantId}`],
  ["patch", `/api/projects/${i.projectId}`, { name: "renamed" }],
  ["delete", `/api/projects/${i.projectId}`],
  ["post", `/api/projects/${i.projectId}/environments`, { name: "qa" }],
  ["put", `/api/projects/${i.projectId}/access/${i.otherId}`, { scope: "project" }],
  ["post", `/api/orgs/${i.orgId}/projects`, { name: "Another" }],
  ["patch", `/api/orgs/${i.orgId}/members/${i.devId}`, { role: "admin" }],
  ["patch", `/api/orgs/${i.orgId}/members/${i.otherId}`, { role: "admin" }],
  ["delete", `/api/orgs/${i.orgId}/members/${i.otherId}`],
  ["post", `/api/orgs/${i.orgId}/invites`, { role: "developer" }],
  ["post", `/api/orgs/${i.orgId}/killswitches`, { scope: "org", scopeId: i.orgId, reason: "testing access" }],
];

const adminReads = (i: Ids): string[] => [
  `/api/orgs/${i.orgId}/audit`,
  `/api/orgs/${i.orgId}/devices`,
  `/api/orgs/${i.orgId}/sessions`,
  `/api/orgs/${i.orgId}/invites`,
  `/api/environments/${i.envId}/webhook-events`,
];

const call = (
  client: Record<Method, (url: string, body?: unknown) => Promise<{ status: number; body: unknown }>>,
  m: Method,
  url: string,
  body?: unknown,
) => (m === "get" || m === "delete" ? client[m](url) : client[m](url, body));

describe("RBAC and scope matrix (Z6, Z7, A7, D8, FR-UI-004)", () => {
  it("Z7 a developer is refused every admin write (FR-UI-004)", async () => {
    const { dev, ids } = await world();
    const allowed: string[] = [];
    for (const [m, url, body] of adminWrites(ids)) {
      const res = await call(dev as never, m, url, body);
      // 404 also refuses (e.g. Connect on a service that isn't a webhook); anything else is a hole.
      if (![403, 404].includes(res.status)) allowed.push(`${m.toUpperCase()} ${url} → ${res.status}`);
    }
    expect(allowed).toEqual([]);
  });

  it("Z7 a developer is refused admin-only lists (audit, devices, sessions, invites, webhook events, profiles)", async () => {
    const { dev, ids } = await world();
    const allowed: string[] = [];
    for (const url of adminReads(ids)) {
      const res = await dev.get(url);
      if (res.status !== 403) allowed.push(`GET ${url} → ${res.status}`);
    }
    expect(allowed).toEqual([]);
  });

  it("Z6 A7 an owner of another org gets 403/404 on every id of this org, and never a value", async () => {
    const { outsider, ids } = await world();
    const leaked: string[] = [];
    const reads: [Method, string][] = [
      ...adminReads(ids).map((u) => ["get", u] as [Method, string]),
      ["get", `/api/environments/${ids.envId}`],
      ["get", `/api/environments/${ids.envId}/resources`],
      ["get", `/api/environments/${ids.envId}/variables`],
      ["get", `/api/environments/${ids.envId}/preview`],
      ["get", `/api/projects/${ids.projectId}`],
      ["get", `/api/orgs/${ids.orgId}/members`],
    ];
    for (const [m, url, body] of [...adminWrites(ids), ...reads] as [Method, string, unknown?][]) {
      const res = await call(outsider as never, m, url, body);
      if (![403, 404].includes(res.status) || JSON.stringify(res.body).includes(SECRET))
        leaked.push(`${m.toUpperCase()} ${url} → ${res.status}`);
    }
    expect(leaked).toEqual([]);
  });

  it("D8 what a developer may read shows names and •••• only", async () => {
    const { dev, ids } = await world();
    for (const url of [
      `/api/environments/${ids.envId}/variables`,
      `/api/environments/${ids.envId}/resources`,
      `/api/projects/${ids.projectId}`,
      `/api/me/devices`,
      `/api/resources/${ids.resourceId}/profiles`, // names only (OQ1)
    ]) {
      const res = await dev.get(url);
      expect(JSON.stringify(res.body)).not.toContain(SECRET);
    }
  });
});
