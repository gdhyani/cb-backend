import type { Express } from "express";
import mongoose from "mongoose";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { createApp } from "../../src/app.js";
import { connectMongo, disconnectMongo } from "../../src/clients/mongodb.client.js";
import { ResourceModel } from "../../src/models/resource.model.js";
import { VariableModel } from "../../src/models/variable.model.js";
import { addMember, signupOwner } from "../helpers/api.js";
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
  vi.restoreAllMocks();
});

async function env() {
  const ctx = await signupOwner(app);
  const p = await ctx.owner.post(`/api/orgs/${ctx.orgId}/projects`, { name: "Shop" });
  const envId = p.body.data.environments[0].id as string;
  return { ...ctx, envId, url: `/api/environments/${envId}/services` };
}

describe("D1 one-step service setup (J2, J3)", () => {
  it("tests, then creates the service and its main brokered variable named by the user", async () => {
    const { owner, url } = await env();
    const res = await owner.post(url, {
      key: "MONGODB_URI",
      resource: { kind: "mongodb", connectionUri: `${mongo.uri}shop` },
    });
    expect(res.status).toBe(201);
    expect(res.body.data.test).toMatchObject({ ok: true, profile: "default" });
    expect(res.body.data.service).toMatchObject({ kind: "mongodb", name: "MONGODB_URI" });
    expect(res.body.data.variables).toEqual([
      expect.objectContaining({
        key: "MONGODB_URI",
        type: "brokered",
        field: "url",
        resourceId: res.body.data.service.id,
      }),
    ]);
  });

  it("SERVICE_TEST_FAILED: a failing test saves nothing and never echoes the secret", async () => {
    const { owner, url } = await env();
    const res = await owner.post(url, {
      key: "REDIS_URL",
      resource: { kind: "redis", connectionUri: "redis://default:LEAKY_PW_31@127.0.0.1:1" },
    });
    expect(res.status).toBe(422);
    expect(res.body.error.code).toBe("SERVICE_TEST_FAILED");
    expect(JSON.stringify(res.body)).not.toContain("LEAKY_PW_31");
    expect(await ResourceModel.countDocuments()).toBe(0);
    expect(await VariableModel.countDocuments()).toBe(0);
  });

  it("D3 applies preset defaults (fake prefix, upstream, redirect hosts) and creates extras", async () => {
    const { owner, url } = await env();
    const res = await owner.post(url, {
      key: "STRIPE_SECRET_KEY",
      preset: "stripe",
      test: false,
      resource: { kind: "http", apiKey: "sk_live_123" },
      extras: [{ key: "NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY", value: "pk_live_9" }],
    });
    expect(res.status).toBe(201);
    expect(res.body.data.test).toBeNull();
    expect(res.body.data.service.config).toMatchObject({
      upstreamUrl: "https://api.stripe.com",
      fakePrefix: "sk_test_cb_",
      redirectHosts: ["api.stripe.com:443"],
      provider: "stripe",
    });
    expect(res.body.data.variables.map((v: { key: string; type: string }) => `${v.key}:${v.type}`)).toEqual([
      "STRIPE_SECRET_KEY:brokered",
      "NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY:plain",
    ]);
    expect(JSON.stringify(res.body)).not.toContain("sk_live_123");
  });

  it("brokered extras use the service's fields (AI base URL)", async () => {
    const { owner, url } = await env();
    const res = await owner.post(url, {
      key: "OPENAI_API_KEY",
      preset: "openai",
      test: false,
      resource: { kind: "http", apiKey: "sk-proj-1" },
      extras: [{ key: "MY_OPENAI_URL", field: "baseUrl" }],
    });
    expect(res.status).toBe(201);
    expect(res.body.data.variables[1]).toMatchObject({
      key: "MY_OPENAI_URL",
      type: "brokered",
      field: "baseUrl",
    });
  });

  it("CONFLICT: an existing key refuses the whole setup; nothing is created", async () => {
    const { owner, envId, url } = await env();
    await owner.post(`/api/environments/${envId}/variables`, {
      type: "plain",
      key: "MONGODB_URI",
      value: "x",
    });
    const res = await owner.post(url, {
      key: "MONGODB_URI",
      test: false,
      resource: { kind: "mongodb", connectionUri: `${mongo.uri}shop` },
    });
    expect(res.status).toBe(409);
    expect(await ResourceModel.countDocuments()).toBe(0);
  });

  it("de-duplicates the hidden service name", async () => {
    const { owner, envId, url } = await env();
    await owner.post(`/api/environments/${envId}/resources`, {
      kind: "mongodb",
      name: "MONGODB_URI",
      connectionUri: `${mongo.uri}a`,
    });
    const res = await owner.post(url, {
      key: "MONGODB_URI",
      test: false,
      resource: { kind: "mongodb", connectionUri: `${mongo.uri}b` },
    });
    expect(res.status).toBe(201);
    expect(res.body.data.service.name).toBe("MONGODB_URI-2");
  });

  it("rejects duplicate keys, unknown presets, preset/kind mismatch and fields the kind cannot broker", async () => {
    const { owner, url } = await env();
    const base = {
      key: "A",
      test: false,
      resource: { kind: "http", upstreamUrl: "https://x.example.com", apiKey: "k" },
    };
    expect((await owner.post(url, { ...base, extras: [{ key: "A", field: "baseUrl" }] })).status).toBe(400);
    expect((await owner.post(url, { ...base, preset: "nope" })).status).toBe(400);
    expect((await owner.post(url, { ...base, preset: "postgres" })).status).toBe(400);
    expect((await owner.post(url, { ...base, extras: [{ key: "B", field: "url" }] })).status).toBe(400);
    expect(await ResourceModel.countDocuments()).toBe(0);
  });

  it("compensates: a failure after the service was created leaves nothing behind", async () => {
    const { owner, url } = await env();
    const real = VariableModel.create.bind(VariableModel);
    let calls = 0;
    vi.spyOn(VariableModel, "create").mockImplementation(((doc: never) => {
      calls += 1;
      if (calls === 2) throw new Error("disk full");
      return real(doc);
    }) as never);
    const res = await owner.post(url, {
      key: "S",
      test: false,
      resource: { kind: "http", upstreamUrl: "https://x.example.com", apiKey: "k" },
      extras: [{ key: "S_URL", field: "baseUrl" }],
    });
    expect(res.status).toBe(500);
    expect(await ResourceModel.countDocuments()).toBe(0);
    expect(await VariableModel.countDocuments()).toBe(0);
  });

  it("FR-UI-004 developers cannot create services", async () => {
    const { owner, orgId, url } = await env();
    const { member } = await addMember(app, owner, orgId, "Dev");
    const res = await member.post(url, {
      key: "A",
      test: false,
      resource: { kind: "redis", connectionUri: "redis://h:6379" },
    });
    expect(res.status).toBe(403);
  });
});
