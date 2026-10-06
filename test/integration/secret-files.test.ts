import type http from "node:http";
import type { AddressInfo } from "node:net";
import mongoose, { Types } from "mongoose";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createApp } from "../../src/app.js";
import { resetFileStore } from "../../src/clients/file-store.client.js";
import { connectMongo, disconnectMongo } from "../../src/clients/mongodb.client.js";
import { loadEnv, setEnv } from "../../src/config/env.js";
import { createCa } from "../../src/crypto/ca.js";
import { resetUpstreamDispatcher } from "../../src/gateway/http/upstream.js";
import { ResourceModel } from "../../src/models/resource.model.js";
import { StoredFileModel } from "../../src/models/stored-file.model.js";
import { createServer } from "../../src/server.js";
import { readResourceSecret } from "../../src/services/resource-secret.service.js";
import { signupOwner } from "../helpers/api.js";
import { testEnvVars } from "../helpers/env.js";
import { startMemoryMongo } from "../helpers/mongo.js";
import { p8Key, pemBodyLines, serviceAccountJson, sweep } from "../helpers/sweep.js";

let backendDb: Awaited<ReturnType<typeof startMemoryMongo>>;
let server: http.Server;

beforeAll(async () => {
  backendDb = await startMemoryMongo();
  setEnv(loadEnv(testEnvVars(backendDb.uri)));
  resetFileStore();
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

async function env() {
  const app = server.listeners("request")[0] as never;
  const { owner, orgId } = await signupOwner(app);
  const project = await owner.post(`/api/orgs/${orgId}/projects`, { name: "Shop" });
  const envId = project.body.data.environments[0].id as string;
  const add = async (key: string, resource: Record<string, unknown>) => {
    const r = await owner.post(`/api/environments/${envId}/services`, { key, test: false, resource });
    if (r.status !== 201) throw new Error(JSON.stringify(r.body));
    return r.body.data.service.id as string;
  };
  return { owner, envId, add };
}

const raw = (id: string) =>
  ResourceModel.findById(id).select("+credentials +credentialsFile").lean() as unknown as Promise<
    Record<string, unknown> & { config: Record<string, unknown>; credentialsFile?: { path: string } }
  >;

describe("uploaded files live in the file store as ciphertext (B10, S1, FR-CRY-001)", () => {
  it("B10 a service-account JSON and a .p8 go to the store; the resource keeps only a reference", async () => {
    const { add } = await env();
    const sa = serviceAccountJson();
    const p8 = p8Key();
    const saId = await add("FIREBASE_SERVICE_ACCOUNT", { kind: "google-sa", serviceAccountJson: sa.json });
    const apnsId = await add("APNS_KEY", {
      kind: "apns",
      keyId: "ABC123DEFG",
      teamId: "TEAM123456",
      privateKey: p8.pem,
    });
    for (const id of [saId, apnsId]) {
      const doc = await raw(id);
      expect(doc.credentials).toBeUndefined();
      expect(doc.credentialsFile?.path).toMatch(
        new RegExp(`^orgs/[0-9a-f]{24}/resources/${id}/credentials-[0-9a-f]{16}\\.enc$`),
      );
    }
    expect(await StoredFileModel.countDocuments()).toBe(2);
    expect(await sweep([...sa.bodyLines, ...p8.bodyLines])).toEqual([]);
    // The gateway still reads the real value, per use.
    expect(JSON.parse(await readResourceSecret(new Types.ObjectId(saId))).private_key).toBe(sa.private_key);
  });

  it("B10 a CA certificate goes to the store; the DTO shows its subject and expiry, not the PEM", async () => {
    const { owner, envId, add } = await env();
    const ca = await createCa("Aiven Project CA");
    const id = await add("DATABASE_URL", {
      kind: "mysql",
      connectionUri: "mysql://u:REAL_PW_FS_1@db.example.com:1/app?ssl-mode=REQUIRED",
      caCert: ca.certPem,
    });
    const doc = await raw(id);
    expect(doc.config.caCert).toBeUndefined();
    expect(doc.config.caCertFile).toMatchObject({ subject: expect.stringContaining("Aiven Project CA") });
    const list = await owner.get(`/api/environments/${envId}/resources`);
    const body = JSON.stringify(list.body);
    for (const line of pemBodyLines(ca.certPem)) expect(body).not.toContain(line);
    expect(body).toContain("Aiven Project CA");
  });

  it("Y3 replacing a file removes the old object; Y5 deleting the service removes every object", async () => {
    const { owner, add } = await env();
    const ca = await createCa("Old CA");
    const id = await add("DATABASE_URL", {
      kind: "mysql",
      connectionUri: "mysql://u:REAL_PW_FS_2@db.example.com:1/app",
      caCert: ca.certPem,
    });
    const firstPath = ((await raw(id)).config.caCertFile as { path: string }).path;
    const next = await createCa("New CA");
    expect((await owner.patch(`/api/resources/${id}`, { caCert: next.certPem })).status).toBe(200);
    expect(await StoredFileModel.countDocuments({ path: firstPath })).toBe(0);
    expect(await StoredFileModel.countDocuments()).toBe(1);
    expect((await owner.patch(`/api/resources/${id}`, { caCert: "" })).status).toBe(200);
    expect(await StoredFileModel.countDocuments()).toBe(0);

    const saId = await add("FIREBASE_SERVICE_ACCOUNT", {
      kind: "google-sa",
      serviceAccountJson: serviceAccountJson().json,
    });
    expect(
      (await owner.patch(`/api/resources/${saId}`, { serviceAccountJson: serviceAccountJson().json })).status,
    ).toBe(200);
    expect(await StoredFileModel.countDocuments()).toBe(1);
    expect((await owner.delete(`/api/resources/${saId}`)).status).toBe(200);
    expect(await StoredFileModel.countDocuments()).toBe(0);
  });
});

describe("migration: existing files into the store (B10)", () => {
  it("dry run changes nothing; --apply moves inline secrets and CAs, and runs again as a no-op", async () => {
    const { migrateFilesToStore } = await import("../../src/migrations/file-store.migration.js");
    const { encryptSecret } = await import("../../src/crypto/envelope.js");
    const { owner, envId } = await env();
    const project = await owner.get(`/api/environments/${envId}`);
    const orgId = new Types.ObjectId();
    const sa = serviceAccountJson();
    const ca = await createCa("Legacy CA");
    const key = Buffer.from(testEnvVars("x").MASTER_KEY ?? "", "base64");
    const base = {
      orgId,
      projectId: new Types.ObjectId(),
      environmentId: new Types.ObjectId(String(project.body.data?.id ?? envId)),
    };
    const legacySa = await ResourceModel.create({
      ...base,
      kind: "google-sa",
      name: "fb",
      config: {},
      credentials: encryptSecret(key, sa.json),
    });
    const legacyDb = await ResourceModel.create({
      ...base,
      kind: "mysql",
      name: "db",
      config: { caCert: ca.certPem },
      credentials: encryptSecret(key, "mysql://u:p@h/db"),
    });

    const dry = await migrateFilesToStore({ apply: false });
    expect(dry.changes).toHaveLength(2);
    expect(await StoredFileModel.countDocuments()).toBe(0);

    const applied = await migrateFilesToStore({ apply: true });
    expect(applied.changes).toHaveLength(2);
    expect((await raw(legacySa._id.toHexString())).credentials).toBeUndefined();
    expect(JSON.parse(await readResourceSecret(legacySa._id)).private_key).toBe(sa.private_key);
    const db = await raw(legacyDb._id.toHexString());
    expect(db.config.caCert).toBeUndefined();
    expect(db.config.caCertFile).toBeTruthy();
    expect(await sweep(sa.bodyLines)).toEqual([]);

    expect((await migrateFilesToStore({ apply: true })).changes).toHaveLength(0);
  });
});

describe("nothing left behind on bulk delete or failure (I4, Y5)", () => {
  const counts = async () => ({
    files: await StoredFileModel.countDocuments(),
    fakeKeys: await mongoose.connection.db?.collection("fakekeys").countDocuments(),
    resources: await ResourceModel.countDocuments(),
  });

  it("I4 deleting an environment removes its services' stored files and fake keys", async () => {
    const { owner, envId, add } = await env();
    await add("FIREBASE_SERVICE_ACCOUNT", {
      kind: "google-sa",
      serviceAccountJson: serviceAccountJson().json,
    });
    const ca = await createCa("Env CA");
    await add("DATABASE_URL", {
      kind: "mysql",
      connectionUri: "mysql://u:REAL_PW_FS_9@db.example.com:1/app",
      caCert: ca.certPem,
    });
    await mongoose.connection.db
      ?.collection("fakekeys")
      .insertOne({
        resourceId: new Types.ObjectId(),
        deviceId: new Types.ObjectId(),
        publicPem: "x",
        privateKey: {},
      });
    const resIds = (await ResourceModel.find({}).lean()).map((r) => r._id);
    await mongoose.connection.db?.collection("fakekeys").updateMany({}, { $set: { resourceId: resIds[0] } });
    expect((await counts()).files).toBe(2);
    expect((await owner.delete(`/api/environments/${envId}`)).status).toBe(200);
    expect(await counts()).toMatchObject({ files: 0, fakeKeys: 0, resources: 0 });
  });

  it("I4 deleting a project removes every stored file of its services", async () => {
    const { owner, envId, add } = await env();
    await add("FIREBASE_SERVICE_ACCOUNT", {
      kind: "google-sa",
      serviceAccountJson: serviceAccountJson().json,
    });
    const projectId = (await owner.get(`/api/environments/${envId}`)).body.data.projectId;
    expect((await owner.delete(`/api/projects/${projectId}`)).status).toBe(200);
    expect(await counts()).toMatchObject({ files: 0, resources: 0 });
  });

  it("I4 a create that fails after the file was stored leaves no object (duplicate name)", async () => {
    const { owner, envId } = await env();
    const body = { kind: "google-sa", name: "firebase", serviceAccountJson: serviceAccountJson().json };
    expect((await owner.post(`/api/environments/${envId}/resources`, body)).status).toBe(201);
    const dup = await owner.post(`/api/environments/${envId}/resources`, {
      ...body,
      serviceAccountJson: serviceAccountJson().json,
    });
    expect(dup.status).toBe(409);
    expect((await counts()).files).toBe(1);
  });

  it("I4 a service whose variable can't be created is rolled back with its stored file", async () => {
    const { owner, envId } = await env();
    expect(
      (
        await owner.post(`/api/environments/${envId}/variables`, {
          type: "plain",
          key: "FIREBASE_PROJECT_ID",
          value: "taken",
        })
      ).status,
    ).toBe(201);
    const r = await owner.post(`/api/environments/${envId}/services`, {
      key: "GOOGLE_APPLICATION_CREDENTIALS",
      mainField: "credentialsFile",
      test: false,
      resource: { kind: "google-sa", serviceAccountJson: serviceAccountJson().json },
      extras: [{ key: "FIREBASE_PROJECT_ID", field: "projectId" }],
    });
    expect(r.status).toBeGreaterThanOrEqual(400);
    expect(await counts()).toMatchObject({ files: 0, resources: 0 });
  });
});
