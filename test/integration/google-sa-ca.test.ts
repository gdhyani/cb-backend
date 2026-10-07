import { createPrivateKey } from "node:crypto";
import type http from "node:http";
import type { AddressInfo } from "node:net";
import mongoose from "mongoose";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createApp } from "../../src/app.js";
import { connectMongo, disconnectMongo } from "../../src/clients/mongodb.client.js";
import { loadEnv, setEnv } from "../../src/config/env.js";
import { createCa } from "../../src/crypto/ca.js";
import { resetUpstreamDispatcher } from "../../src/gateway/http/upstream.js";
import { createServer } from "../../src/server.js";
import { addMember, cli, loginDevice, signupOwner } from "../helpers/api.js";
import { testEnvVars } from "../helpers/env.js";
import { startMemoryMongo } from "../helpers/mongo.js";
import { pemBodyLines, serviceAccountJson, sweep } from "../helpers/sweep.js";

let backendDb: Awaited<ReturnType<typeof startMemoryMongo>>;
let server: http.Server;

beforeAll(async () => {
  backendDb = await startMemoryMongo();
  setEnv(loadEnv(testEnvVars(backendDb.uri)));
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
});
beforeEach(async () => {
  await mongoose.connection.db?.dropDatabase();
});

/** As a file saved on Windows: BOM + CRLF line endings + trailing newline. */
const windowsFile = (text: string) => `﻿${text.replace(/\n/g, "\r\n")}\r\n`;

async function env() {
  const app = server.listeners("request")[0] as never;
  const { owner, orgId } = await signupOwner(app);
  const project = await owner.post(`/api/orgs/${orgId}/projects`, { name: "Shop" });
  const envId = project.body.data.environments[0].id as string;
  return {
    app,
    owner,
    orgId,
    envId,
    projectId: project.body.data.id as string,
    services: `/api/environments/${envId}/services`,
  };
}

describe("Firebase service-account JSON (google-sa, FR-CRY-004)", () => {
  it("Firebase: a key file saved on Windows (BOM + CRLF) is accepted", async () => {
    const { owner, services } = await env();
    const res = await owner.post(services, {
      key: "FIREBASE_SERVICE_ACCOUNT",
      test: false,
      resource: { kind: "google-sa", serviceAccountJson: windowsFile(serviceAccountJson().json) },
    });
    expect(res.status, JSON.stringify(res.body)).toBe(201);
  });

  it("Firebase: a file that is not a service-account key is refused with a named reason, never echoing it", async () => {
    const { owner, services } = await env();
    const sa = JSON.parse(serviceAccountJson().json) as Record<string, string>;
    const tries: [Record<string, unknown>, RegExp][] = [
      [{ ...sa, type: "authorized_user" }, /service.account/i],
      [{ ...sa, private_key: undefined }, /private_key/],
      [
        { ...sa, private_key: "-----BEGIN PRIVATE KEY-----\nnot-a-key\n-----END PRIVATE KEY-----\n" },
        /private_key/,
      ],
    ];
    for (const [json, reason] of tries) {
      const res = await owner.post(services, {
        key: "FIREBASE_SERVICE_ACCOUNT",
        test: false,
        resource: { kind: "google-sa", serviceAccountJson: JSON.stringify(json) },
      });
      expect(res.status).toBe(400);
      expect(JSON.stringify(res.body.error)).toMatch(reason);
      for (const line of pemBodyLines(sa.private_key ?? ""))
        expect(JSON.stringify(res.body)).not.toContain(line);
    }
  });

  it("F6 the device's file is a fake service account: parseable, same client_email, a different private key", async () => {
    const { app, owner, orgId, envId, projectId, services } = await env();
    const sa = serviceAccountJson();
    const created = await owner.post(services, {
      key: "GOOGLE_APPLICATION_CREDENTIALS",
      mainField: "credentialsFile",
      test: false,
      resource: { kind: "google-sa", serviceAccountJson: sa.json },
    });
    expect(created.status, JSON.stringify(created.body)).toBe(201);
    const bob = await addMember(app, owner, orgId, "Bob");
    await owner.post(`/api/environments/${envId}/grants`, { userId: bob.userId });
    const { token } = await loginDevice(app, bob.member);
    const boot = await cli(app, token).get(`/api/agent/bootstrap?projectId=${projectId}&env=development`);
    const file = boot.body.data.files?.GOOGLE_APPLICATION_CREDENTIALS as string;
    expect(file).toBeTruthy();
    const fake = JSON.parse(file) as Record<string, string>;
    expect(fake.client_email).toBe("sa@cb-test.iam.gserviceaccount.com");
    expect(() => createPrivateKey(fake.private_key ?? "")).not.toThrow();
    expect(fake.private_key).not.toBe(sa.private_key);
    for (const line of sa.bodyLines) expect(JSON.stringify(boot.body)).not.toContain(line);
  });

  it("Y3 replacing the service account leaves no trace of the old key", async () => {
    const { owner, services } = await env();
    const old = serviceAccountJson();
    const created = await owner.post(services, {
      key: "FIREBASE_SERVICE_ACCOUNT",
      test: false,
      resource: { kind: "google-sa", serviceAccountJson: old.json },
    });
    const next = serviceAccountJson();
    const res = await owner.patch(`/api/resources/${created.body.data.service.id}`, {
      serviceAccountJson: next.json,
    });
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(await sweep([...old.bodyLines, ...next.bodyLines])).toEqual([]);
  });
});

describe("CA certificates for private-CA databases (Aiven, FR-GW-004)", () => {
  it("CA: a CA file saved on Windows (BOM + CRLF) is accepted", async () => {
    const { owner, services } = await env();
    const ca = await createCa("Aiven-like project CA");
    const res = await owner.post(services, {
      key: "DATABASE_URL",
      test: false,
      resource: {
        kind: "mysql",
        connectionUri: "mysql://u:REAL_PW_CA_001@db.example.com:12345/defaultdb?ssl-mode=REQUIRED",
        caCert: windowsFile(ca.certPem),
      },
    });
    expect(res.status, JSON.stringify(res.body)).toBe(201);
  });

  it("S1 the service's CA stays in the backend: never in the device bootstrap", async () => {
    const { app, owner, orgId, envId, projectId, services } = await env();
    const ca = await createCa("private CA");
    const created = await owner.post(services, {
      key: "DATABASE_URL",
      test: false,
      resource: {
        kind: "mysql",
        connectionUri: "mysql://u:REAL_PW_CA_002@db.example.com:12345/app?ssl-mode=REQUIRED",
        caCert: ca.certPem,
      },
    });
    expect(created.status).toBe(201);
    const bob = await addMember(app, owner, orgId, "Bob");
    await owner.post(`/api/environments/${envId}/grants`, { userId: bob.userId });
    const { token } = await loginDevice(app, bob.member);
    const boot = await cli(app, token).get(`/api/agent/bootstrap?projectId=${projectId}&env=development`);
    const body = JSON.stringify(boot.body);
    for (const line of pemBodyLines(ca.certPem)) expect(body).not.toContain(line);
    expect(body).not.toContain("REAL_PW_CA_002");
  });

  it('CA: caCert "" removes it', async () => {
    const { owner, services } = await env();
    const ca = await createCa("private CA");
    const created = await owner.post(services, {
      key: "DATABASE_URL",
      test: false,
      resource: {
        kind: "mysql",
        connectionUri: "mysql://u:REAL_PW_CA_003@db.example.com:12345/app",
        caCert: ca.certPem,
      },
    });
    const id = created.body.data.service.id as string;
    expect((await owner.patch(`/api/resources/${id}`, { caCert: "" })).status).toBe(200);
    const after = await owner.get(
      `/api/environments/${created.body.data.service.environmentId ?? ""}/resources`,
    );
    const row = (after.body.data as { id: string; config: Record<string, unknown> }[] | undefined)?.find(
      (r) => r.id === id,
    );
    expect(row?.config.caCert ?? null).toBeNull();
  });

  it("CA: a private key pasted as a CA is refused, without echoing it", async () => {
    const { owner, services } = await env();
    const sa = serviceAccountJson();
    const res = await owner.post(services, {
      key: "DATABASE_URL",
      test: false,
      resource: { kind: "mysql", connectionUri: "mysql://u:p@db.example.com:1/app", caCert: sa.private_key },
    });
    expect(res.status).toBe(400);
    for (const line of sa.bodyLines) expect(JSON.stringify(res.body)).not.toContain(line);
  });
});
