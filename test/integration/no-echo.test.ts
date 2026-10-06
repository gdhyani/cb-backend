import type http from "node:http";
import type { AddressInfo } from "node:net";
import { Writable } from "node:stream";
import mongoose from "mongoose";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { transports } from "winston";
import { createApp } from "../../src/app.js";
import { connectMongo, disconnectMongo } from "../../src/clients/mongodb.client.js";
import { loadEnv, setEnv } from "../../src/config/env.js";
import { resetUpstreamDispatcher } from "../../src/gateway/http/upstream.js";
import { logger } from "../../src/logger/logger.js";
import { createServer } from "../../src/server.js";
import { signupOwner } from "../helpers/api.js";
import { testEnvVars } from "../helpers/env.js";
import { startMockProvider } from "../helpers/mock-provider.js";
import { startMemoryMongo } from "../helpers/mongo.js";
import { p8Key, serviceAccountJson } from "../helpers/sweep.js";

const ACCEPTED = "REAL_NO_ECHO_ACCEPTED_KEY_0";
let backendDb: Awaited<ReturnType<typeof startMemoryMongo>>;
let provider: Awaited<ReturnType<typeof startMockProvider>>;
let server: http.Server;
let lines: string[] = [];

beforeAll(async () => {
  [backendDb, provider] = await Promise.all([
    startMemoryMongo(),
    startMockProvider(ACCEPTED, "the-right-client-secret"),
  ]);
  setEnv(loadEnv({ ...testEnvVars(backendDb.uri), UPSTREAM_EXTRA_CA_FILE: provider.caFile }));
  resetUpstreamDispatcher();
  await connectMongo(backendDb.uri);
  // S9: everything the backend logs during these flows, at debug level.
  logger.add(
    new transports.Stream({
      stream: new Writable({
        write(chunk, _enc, cb) {
          lines.push(chunk.toString());
          cb();
        },
      }),
    }),
  );
  logger.level = "debug";
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
  lines = [];
  await mongoose.connection.db?.dropDatabase();
});

function forms(v: string): string[] {
  return [v, Buffer.from(v).toString("base64"), encodeURIComponent(v)];
}

function expectNoEcho(body: unknown, secrets: string[]) {
  const all = JSON.stringify(body) + lines.join("\n");
  for (const s of secrets) for (const f of forms(s)) expect(all, `echoed ${s.slice(0, 6)}…`).not.toContain(f);
}

async function env() {
  const app = server.listeners("request")[0] as never;
  const { owner, orgId } = await signupOwner(app);
  const project = await owner.post(`/api/orgs/${orgId}/projects`, { name: "Shop" });
  const envId = project.body.data.environments[0].id as string;
  return { owner, envId, url: `/api/environments/${envId}/services` };
}

type Case = { kind: string; secrets: string[]; resource: () => Record<string, unknown> };

const cases = (): Case[] => {
  const sa = serviceAccountJson("sa@cb-test.iam.gserviceaccount.com", `${provider.url}/token`);
  const p8 = p8Key();
  return [
    {
      kind: "http",
      secrets: ["REAL_WRONG_HTTP_KEY_111"],
      resource: () => ({
        kind: "http",
        upstreamUrl: provider.url,
        apiKey: "REAL_WRONG_HTTP_KEY_111",
        testPath: "/v1/models",
      }),
    },
    {
      kind: "aws",
      secrets: ["AKIAREALNOECHO000222", "REAL_WRONG_AWS_SECRET_00000000000222"],
      resource: () => ({
        kind: "aws",
        region: "us-east-1",
        endpoint: provider.url,
        accessKeyId: "AKIAREALNOECHO000222",
        secretAccessKey: "REAL_WRONG_AWS_SECRET_00000000000222",
      }),
    },
    {
      kind: "oauth",
      secrets: ["REAL_WRONG_CLIENT_SECRET_333"],
      resource: () => ({
        kind: "oauth",
        tokenUrl: `${provider.url}/token`,
        clientSecret: "REAL_WRONG_CLIENT_SECRET_333",
      }),
    },
    {
      kind: "google-sa",
      secrets: sa.bodyLines,
      resource: () => ({ kind: "google-sa", serviceAccountJson: sa.json }),
    },
    {
      kind: "apns",
      secrets: p8.bodyLines,
      resource: () => ({
        kind: "apns",
        keyId: "ABC123DEFG",
        teamId: "TEAM123456",
        privateKey: p8.pem,
        upstreamUrl: provider.url,
      }),
    },
    {
      kind: "redis",
      secrets: ["REAL_WRONG_REDIS_PW_444"],
      resource: () => ({
        kind: "redis",
        connectionUri: "redis://default:REAL_WRONG_REDIS_PW_444@127.0.0.1:1",
      }),
    },
    {
      kind: "mongodb",
      secrets: ["REAL_WRONG_MONGO_PW_555"],
      resource: () => ({
        kind: "mongodb",
        connectionUri: "mongodb://root:REAL_WRONG_MONGO_PW_555@127.0.0.1:1/app?authSource=admin",
      }),
    },
    {
      kind: "postgres",
      secrets: ["REAL_WRONG_PG_PW_666"],
      resource: () => ({
        kind: "postgres",
        connectionUri: "postgresql://app:REAL_WRONG_PG_PW_666@127.0.0.1:1/app",
      }),
    },
    {
      kind: "mysql",
      secrets: ["REAL_WRONG_MYSQL_PW_777"],
      resource: () => ({
        kind: "mysql",
        connectionUri: "mysql://app:REAL_WRONG_MYSQL_PW_777@127.0.0.1:1/app",
      }),
    },
    {
      kind: "smtp",
      secrets: ["REAL_WRONG_SMTP_PW_888"],
      resource: () => ({ kind: "smtp", connectionUri: "smtps://user:REAL_WRONG_SMTP_PW_888@127.0.0.1:1" }),
    },
  ];
};

describe("no value echoed in errors or logs (S9, L4, B3, B4)", () => {
  it("L4 B4 S9 a failing Save & test never echoes the value, for every kind (body or log)", async () => {
    for (const c of cases()) {
      lines = [];
      const { owner, url } = await env();
      const res = await owner.post(url, {
        key: `${c.kind.toUpperCase().replace("-", "_")}_KEY`,
        resource: c.resource(),
      });
      // OAuth Save & test only proves the token URL answers (no client id to pair the secret with) — by design.
      const expected = c.kind === "oauth" ? [201] : [400, 422];
      expect(expected, `${c.kind} → ${res.status}`).toContain(res.status);
      expect(lines.length, `${c.kind}: the log capture saw nothing`).toBeGreaterThan(0);
      expectNoEcho(res.body, c.secrets);
      await mongoose.connection.db?.dropDatabase();
    }
  });

  it("L4 a failing Replace value (PATCH test:true) never echoes the new value", async () => {
    const { owner, url } = await env();
    const ok = await owner.post(url, {
      key: "API_KEY",
      test: false,
      resource: { kind: "http", upstreamUrl: provider.url, apiKey: ACCEPTED, testPath: "/v1/models" },
    });
    expect(ok.status).toBe(201);
    lines = [];
    const res = await owner.patch(`/api/resources/${ok.body.data.service.id}`, {
      apiKey: "REAL_WRONG_REPLACEMENT_999",
      test: true,
    });
    expect(res.status).toBe(422);
    expectNoEcho(res.body, ["REAL_WRONG_REPLACEMENT_999", ACCEPTED]);
  });

  it("B4 VALIDATION_FAILED details never repeat the submitted secret", async () => {
    const { owner, url } = await env();
    for (const resource of [
      { kind: "google-sa", serviceAccountJson: "{not json CANARY_SA_VALUE_123" },
      { kind: "mysql", connectionUri: "mysql://u:CANARY_PW_VALUE_123@h/db", caCert: "CANARY_PEM_VALUE_123" },
      { kind: "apns", keyId: "ABC123DEFG", teamId: "TEAM123456", privateKey: "CANARY_P8_VALUE_123" },
      { kind: "webhook", provider: "stripe", path: "/hooks", signingSecret: "CANARY_NOT_WHSEC_123" },
    ]) {
      lines = [];
      const res = await owner.post(url, { key: "SOME_KEY", resource });
      expect(res.status, JSON.stringify(resource.kind)).toBe(400);
      expectNoEcho(res.body, [
        "CANARY_SA_VALUE_123",
        "CANARY_PW_VALUE_123",
        "CANARY_PEM_VALUE_123",
        "CANARY_P8_VALUE_123",
        "CANARY_NOT_WHSEC_123",
      ]);
    }
  });
});
