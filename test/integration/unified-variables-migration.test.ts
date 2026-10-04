import type { Express } from "express";
import mongoose from "mongoose";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createApp } from "../../src/app.js";
import { connectMongo, disconnectMongo } from "../../src/clients/mongodb.client.js";
import { migrateUnifiedVariables } from "../../src/migrations/unified-variables.migration.js";
import { ResourceModel } from "../../src/models/resource.model.js";
import { VariableModel } from "../../src/models/variable.model.js";
import { signupOwner } from "../helpers/api.js";
import { useTestEnv } from "../helpers/env.js";
import { startMemoryMongo } from "../helpers/mongo.js";

let mongo: Awaited<ReturnType<typeof startMemoryMongo>>;
let app: Express;
beforeAll(async () => {
  mongo = await startMemoryMongo();
  useTestEnv(mongo.uri);
  await connectMongo(mongo.uri);
  app = createApp();
});
afterAll(async () => {
  await disconnectMongo();
  await mongo.stop();
});
beforeEach(async () => {
  await mongoose.connection.db?.dropDatabase();
});

/** Data as the old two-page flow created it. */
async function legacyEnvironment() {
  const { owner, orgId } = await signupOwner(app);
  const p = await owner.post(`/api/orgs/${orgId}/projects`, { name: "Legacy" });
  const envId = p.body.data.environments[0].id as string;
  const res = (body: object) => owner.post(`/api/environments/${envId}/resources`, body);
  const v = (body: object) => owner.post(`/api/environments/${envId}/variables`, body);
  const stripe = await res({
    kind: "http",
    name: "stripe",
    upstreamUrl: "https://api.stripe.com",
    apiKey: "sk_live_x",
  });
  const oauth = await res({
    kind: "oauth",
    name: "sign-in",
    tokenUrl: "https://oauth2.googleapis.com/token",
    clientSecret: "s",
  });
  const mailer = await res({
    kind: "smtp",
    name: "mailer",
    connectionUri: "smtp://u:p@mail.example.com:587",
  });
  const db = await res({
    kind: "mongodb",
    name: "shop-db",
    connectionUri: "mongodb://u:p@db.example.com:27017/shop",
  });
  // A service whose main key name is already taken by another service's name.
  await res({ kind: "redis", name: "REDIS_URL", connectionUri: "redis://h:6379" });
  const cache2 = await res({ kind: "redis", name: "cache-2", connectionUri: "redis://h2:6379" });
  await v({ type: "brokered", key: "STRIPE_SECRET_KEY", resourceId: stripe.body.data.id, field: "key" });
  await v({
    type: "brokered",
    key: "OAUTH_CLIENT_SECRET",
    resourceId: oauth.body.data.id,
    field: "clientSecret",
  });
  await v({ type: "plain", key: "OAUTH_CLIENT_ID", value: "client-123" });
  await v({ type: "plain", key: "APP_NAME", value: "shop" });
  await v({ type: "brokered", key: "SMTP_HOST", resourceId: mailer.body.data.id, field: "host" });
  await v({ type: "brokered", key: "MONGODB_URI", resourceId: db.body.data.id, field: "url" });
  await v({ type: "brokered", key: "REDIS_URL", resourceId: cache2.body.data.id, field: "url" });
  return {
    envId,
    ids: {
      stripe: stripe.body.data.id,
      oauth: oauth.body.data.id,
      mailer: mailer.body.data.id,
      db: db.body.data.id,
      cache2: cache2.body.data.id,
    },
  };
}

const resource = async (id: string) => ResourceModel.findById(id).lean();

describe("v1.26 migration: existing data in the Unified Variables format", () => {
  it("dry run reports every change and writes nothing", async () => {
    const { ids } = await legacyEnvironment();
    const report = await migrateUnifiedVariables({ apply: false });
    expect(report.changes.length).toBeGreaterThan(0);
    expect((await resource(ids.stripe))?.name).toBe("stripe");
    expect((await resource(ids.stripe))?.config).not.toHaveProperty("provider");
  });

  it("names services after their main key, records presets, links extra keys — and is idempotent", async () => {
    const { ids } = await legacyEnvironment();
    await migrateUnifiedVariables({ apply: true });

    const stripe = await resource(ids.stripe);
    expect(stripe?.name).toBe("STRIPE_SECRET_KEY");
    expect(stripe?.config).toMatchObject({ provider: "stripe", testPath: "/v1/balance" });
    expect((await resource(ids.db))?.name).toBe("MONGODB_URI");
    expect((await resource(ids.oauth))?.name).toBe("OAUTH_CLIENT_SECRET");
    // No variable on the main field: the name stays.
    expect((await resource(ids.mailer))?.name).toBe("mailer");
    // The main key's name is taken by another service: the name stays.
    expect((await resource(ids.cache2))?.name).toBe("cache-2");

    const clientId = await VariableModel.findOne({ key: "OAUTH_CLIENT_ID" }).lean();
    expect(String(clientId?.resourceId)).toBe(ids.oauth);
    expect(clientId?.type).toBe("plain");
    expect((await VariableModel.findOne({ key: "APP_NAME" }).lean())?.resourceId ?? null).toBeNull();

    const again = await migrateUnifiedVariables({ apply: true });
    expect(again.changes).toEqual([]);
  });

  it("never touches credentials", async () => {
    const { ids } = await legacyEnvironment();
    const before = await ResourceModel.findById(ids.stripe).select("+credentials").lean();
    await migrateUnifiedVariables({ apply: true });
    const after = await ResourceModel.findById(ids.stripe).select("+credentials").lean();
    expect(after?.credentials).toEqual(before?.credentials);
  });
});
