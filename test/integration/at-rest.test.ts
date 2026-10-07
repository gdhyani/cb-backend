import type http from "node:http";
import type { AddressInfo } from "node:net";
import mongoose, { Types } from "mongoose";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createApp } from "../../src/app.js";
import { connectMongo, disconnectMongo } from "../../src/clients/mongodb.client.js";
import { loadEnv, setEnv } from "../../src/config/env.js";
import { encryptSecret } from "../../src/crypto/envelope.js";
import { resetUpstreamDispatcher } from "../../src/gateway/http/upstream.js";
import { FakeKeyModel } from "../../src/models/fake-key.model.js";
import { TokenSwapModel } from "../../src/models/token-swap.model.js";
import { createServer } from "../../src/server.js";
import { addMember, cli, loginDevice, signupOwner } from "../helpers/api.js";
import { testEnvVars } from "../helpers/env.js";
import { startMockProvider } from "../helpers/mock-provider.js";
import { startMemoryMongo } from "../helpers/mongo.js";
import { p8Key, serviceAccountJson, sweep } from "../helpers/sweep.js";

const HTTP_KEY = "REAL_AT_REST_HTTP_KEY_001";
const AWS_SECRET = "REAL_AT_REST_AWS_SECRET_0000000000002";
const AWS_ID = "AKIAREALATREST000003";
const OAUTH_SECRET = "REAL_AT_REST_OAUTH_SECRET_004";
const WH_SECRET = "whsec_REAL_AT_REST_WEBHOOK_005";
const REDIS_PW = "REAL_AT_REST_REDIS_PW_006";
let backendDb: Awaited<ReturnType<typeof startMemoryMongo>>;
let provider: Awaited<ReturnType<typeof startMockProvider>>;
let server: http.Server;

beforeAll(async () => {
  [backendDb, provider] = await Promise.all([startMemoryMongo(), startMockProvider(HTTP_KEY)]);
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

async function env() {
  const app = server.listeners("request")[0] as never;
  const { owner, orgId } = await signupOwner(app);
  const project = await owner.post(`/api/orgs/${orgId}/projects`, { name: "Shop" });
  const envId = project.body.data.environments[0].id as string;
  const create = async (body: Record<string, unknown>) => {
    const r = await owner.post(`/api/environments/${envId}/resources`, body);
    if (r.status !== 201) throw new Error(JSON.stringify(r.body));
    return r.body.data.id as string;
  };
  return { app, owner, orgId, envId, projectId: project.body.data.id as string, create };
}

describe("secrets at rest (B2, S2, Y3, Y5)", () => {
  it("B2 S2 no collection holds a real secret in plaintext, for every kind", async () => {
    const { create } = await env();
    const sa = serviceAccountJson();
    const p8 = p8Key();
    await create({ kind: "http", name: "api", upstreamUrl: provider.url, apiKey: HTTP_KEY });
    await create({
      kind: "redis",
      name: "cache",
      connectionUri: `redis://default:${REDIS_PW}@127.0.0.1:6399`,
    });
    await create({
      kind: "aws",
      name: "s3",
      region: "us-east-1",
      endpoint: provider.url,
      accessKeyId: AWS_ID,
      secretAccessKey: AWS_SECRET,
    });
    await create({
      kind: "oauth",
      name: "google",
      tokenUrl: `${provider.url}/token`,
      clientSecret: OAUTH_SECRET,
    });
    await create({ kind: "google-sa", name: "firebase", serviceAccountJson: sa.json });
    await create({
      kind: "apns",
      name: "push",
      keyId: "ABC123DEFG",
      teamId: "TEAM123456",
      privateKey: p8.pem,
    });
    await create({
      kind: "webhook",
      name: "stripe-hooks",
      provider: "stripe",
      path: "/webhooks/stripe",
      signingSecret: WH_SECRET,
    });
    expect(
      await sweep([
        HTTP_KEY,
        REDIS_PW,
        AWS_SECRET,
        OAUTH_SECRET,
        WH_SECRET,
        ...sa.bodyLines,
        ...p8.bodyLines,
      ]),
    ).toEqual([]);
  });

  it("Y3 replacing a value leaves no trace of the old one", async () => {
    const { owner, create } = await env();
    const id = await create({ kind: "http", name: "api", upstreamUrl: provider.url, apiKey: HTTP_KEY });
    const res = await owner.patch(`/api/resources/${id}`, { apiKey: "REAL_AT_REST_NEW_KEY_777" });
    expect(res.status).toBe(200);
    expect(await sweep([HTTP_KEY, "REAL_AT_REST_NEW_KEY_777"])).toEqual([]);
  });

  it("Y5 deleting a Firebase service removes its token swaps and fake keys", async () => {
    const { app, owner, orgId, envId, projectId, create } = await env();
    const id = await create({
      kind: "google-sa",
      name: "firebase",
      serviceAccountJson: serviceAccountJson().json,
    });
    await owner.post(`/api/environments/${envId}/variables`, {
      type: "brokered",
      key: "GOOGLE_APPLICATION_CREDENTIALS",
      resourceId: id,
      field: "credentialsFile",
    });
    const bob = await addMember(app, owner, orgId, "Bob");
    await owner.post(`/api/environments/${envId}/grants`, { userId: bob.userId });
    const { token, deviceId } = await loginDevice(app, bob.member);
    const boot = await cli(app, token).get(`/api/agent/bootstrap?projectId=${projectId}&env=development`);
    expect(boot.status).toBe(200);
    const resourceId = new Types.ObjectId(id);
    expect(await FakeKeyModel.countDocuments({ resourceId })).toBe(1);
    await TokenSwapModel.create({
      fakeHash: "h1",
      deviceId: new Types.ObjectId(deviceId),
      resourceId,
      real: encryptSecret(
        Buffer.from(testEnvVars(backendDb.uri).MASTER_KEY, "base64"),
        "ya29.REAL_TOKEN_123",
      ),
      expiresAt: new Date(Date.now() + 3_600_000),
    });

    expect((await owner.delete(`/api/resources/${id}`)).status).toBe(200);
    expect(await FakeKeyModel.countDocuments({ resourceId })).toBe(0);
    expect(await TokenSwapModel.countDocuments({ resourceId })).toBe(0);
  });
});
