import fs from "node:fs";
import type http from "node:http";
import https from "node:https";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import { GetObjectCommand, S3Client } from "@aws-sdk/client-s3";
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

const REAL_ID = "AKIAREALID0000000042";
const REAL_SECRET = "REALSECRETaws/0000000000000000000000000042";
let backendDb: Awaited<ReturnType<typeof startMemoryMongo>>;
let s3: https.Server;
let s3Url: string;
let seen: { body: string; headers: Record<string, string> } = { body: "", headers: {} };
let server: http.Server;
let base: string;

beforeAll(async () => {
  backendDb = await startMemoryMongo();
  const ca = await createCa("fake S3 CA");
  const leaf = await mintLeaf(ca, "localhost");
  const caFile = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "cb-s3-ca-")), "ca.pem");
  fs.writeFileSync(caFile, ca.certPem);
  // An S3 that refuses every request the way AWS does: the error XML names the access key id it was given.
  s3 = https.createServer({ cert: leaf.certPem, key: leaf.keyPem }, (req, res) => {
    req.resume();
    const id = /Credential=([^/]+)/.exec(String(req.headers.authorization))?.[1] ?? "";
    res.writeHead(403, { "content-type": "application/xml", "x-amz-debug": `key ${id}` });
    res.end(
      `<?xml version="1.0"?><Error><Code>InvalidAccessKeyId</Code><Message>The AWS Access Key Id you provided does not exist.</Message><AWSAccessKeyId>${id}</AWSAccessKeyId><StringToSign>AWS4-HMAC-SHA256 ${id}</StringToSign></Error>`,
    );
  });
  await new Promise<void>((r) => s3.listen(0, "127.0.0.1", r));
  s3Url = `https://localhost:${(s3.address() as AddressInfo).port}`;
  setEnv(loadEnv({ ...testEnvVars(backendDb.uri), UPSTREAM_EXTRA_CA_FILE: caFile }));
  resetUpstreamDispatcher();
  await connectMongo(backendDb.uri);
  server = createServer(createApp()).server;
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}, 120_000);
afterAll(async () => {
  server.closeAllConnections();
  server.close();
  s3.close();
  await disconnectMongo();
  await backendDb.stop();
});
beforeEach(async () => {
  await mongoose.connection.db?.dropDatabase();
});

describe("AWS provider errors (N8, S8, FR-GW-006)", () => {
  it("N8 S8 S3 error XML and headers never carry the real access key id or secret", async () => {
    const app = server.listeners("request")[0] as never;
    const { owner, orgId } = await signupOwner(app);
    const project = await owner.post(`/api/orgs/${orgId}/projects`, { name: "Shop" });
    const envId = project.body.data.environments[0].id as string;
    const res = await owner.post(`/api/environments/${envId}/resources`, {
      kind: "aws",
      name: "uploads",
      region: "us-east-1",
      endpoint: s3Url,
      accessKeyId: REAL_ID,
      secretAccessKey: REAL_SECRET,
    });
    if (res.status !== 201) throw new Error(JSON.stringify(res.body));
    const resourceId = res.body.data.id as string;
    for (const [key, field] of [
      ["AWS_ACCESS_KEY_ID", "accessKeyId"],
      ["AWS_SECRET_ACCESS_KEY", "secretAccessKey"],
      ["AWS_REGION", "region"],
    ])
      await owner.post(`/api/environments/${envId}/variables`, { type: "brokered", key, resourceId, field });
    const bob = await addMember(app, owner, orgId, "Bob");
    await owner.post(`/api/environments/${envId}/grants`, { userId: bob.userId });
    const { token } = await loginDevice(app, bob.member);
    const boot = await cli(app, token).get(
      `/api/agent/bootstrap?projectId=${project.body.data.id}&env=development`,
    );
    const plain = boot.body.data.plain as Record<string, string>;
    const listener = await localListener(base, token, { layer: "1", env: envId, resource: resourceId });

    // Raw request: capture exactly what reaches the app.
    const client = new S3Client({
      region: "us-east-1",
      endpoint: `http://127.0.0.1:${listener.port}`,
      forcePathStyle: true,
      credentials: {
        accessKeyId: plain.AWS_ACCESS_KEY_ID ?? "",
        secretAccessKey: plain.AWS_SECRET_ACCESS_KEY ?? "",
      },
    });
    client.middlewareStack.add(
      (next) => async (args) => {
        const out = await next(args);
        const response = out.response as { headers: Record<string, string> };
        seen = { body: "", headers: response.headers };
        return out;
      },
      { step: "deserialize", priority: "low" },
    );
    const err = await client
      .send(new GetObjectCommand({ Bucket: "b", Key: "cb.png" }))
      .catch((e: unknown) => e);
    const raw = await fetch(`http://127.0.0.1:${listener.port}/b/cb.png`, {
      headers: { authorization: "AWS4-HMAC-SHA256 Credential=x" },
    }).catch(() => undefined);
    seen.body = raw ? await raw.text() : "";
    listener.close();

    const everything = JSON.stringify([err, seen]);
    expect(everything).toContain("InvalidAccessKeyId"); // the provider's error still reaches the app
    expect(everything).not.toContain(REAL_ID);
    expect(everything).not.toContain(REAL_SECRET);
  });
});
