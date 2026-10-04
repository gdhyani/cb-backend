import { generateKeyPairSync } from "node:crypto";
import type http from "node:http";
import http2 from "node:http2";
import type { AddressInfo } from "node:net";
import tls from "node:tls";
import mongoose from "mongoose";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createWebSocketStream, WebSocket } from "ws";
import { createApp } from "../../src/app.js";
import { connectMongo, disconnectMongo } from "../../src/clients/mongodb.client.js";
import { loadEnv, setEnv } from "../../src/config/env.js";
import { signJwt } from "../../src/crypto/jwt.js";
import { resetUpstreamDispatcher } from "../../src/gateway/http/upstream.js";
import { createServer } from "../../src/server.js";
import { cli, loginDevice, signupOwner } from "../helpers/api.js";
import { testEnvVars } from "../helpers/env.js";
import { startMockPush } from "../helpers/mock-push.js";
import { startMemoryMongo } from "../helpers/mongo.js";

// Real keys exist only in this process and the mock upstream; the device only ever sees fakes.
const google = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});
const apple = generateKeyPairSync("ec", {
  namedCurve: "P-256",
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});
const CLIENT_EMAIL = "firebase-adminsdk@cb-shop.iam.gserviceaccount.com";
const REAL_ACCESS_TOKEN = "ya29.REAL_GOOGLE_ACCESS_TOKEN_5521";
const KEY_ID = "ABC123DEFG";
const TEAM_ID = "TEAM456XYZ";
const SERVICE_ACCOUNT = JSON.stringify({
  type: "service_account",
  project_id: "cb-shop",
  private_key_id: "real-key-id-1",
  private_key: google.privateKey,
  client_email: CLIENT_EMAIL,
  token_uri: "https://oauth2.googleapis.com/token",
});

let backendDb: Awaited<ReturnType<typeof startMemoryMongo>>;
let upstream: Awaited<ReturnType<typeof startMockPush>>;
let server: http.Server;
let base: string;

beforeAll(async () => {
  [backendDb, upstream] = await Promise.all([
    startMemoryMongo(),
    startMockPush({
      google: { clientEmail: CLIENT_EMAIL, publicPem: google.publicKey, accessToken: REAL_ACCESS_TOKEN },
      apns: { keyId: KEY_ID, teamId: TEAM_ID, publicPem: apple.publicKey },
    }),
  ]);
  setEnv(loadEnv({ ...testEnvVars(backendDb.uri), UPSTREAM_EXTRA_CA_FILE: upstream.caFile }));
  resetUpstreamDispatcher();
  await connectMongo(backendDb.uri);
  server = createServer(createApp()).server;
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}, 120_000);
afterAll(async () => {
  server.closeAllConnections();
  server.close();
  await disconnectMongo();
  await backendDb.stop();
  upstream.close();
});
beforeEach(async () => {
  await mongoose.connection.db?.dropDatabase();
});

async function scenario() {
  const app = server.listeners("request")[0] as never;
  const { owner, orgId } = await signupOwner(app);
  const project = await owner.post(`/api/orgs/${orgId}/projects`, { name: "Push" });
  const envId = project.body.data.environments[0].id as string;
  const fcm = await owner.post(`/api/environments/${envId}/resources`, {
    kind: "google-sa",
    name: "firebase",
    serviceAccountJson: SERVICE_ACCOUNT,
    upstreamUrl: upstream.url,
  });
  if (fcm.status !== 201) throw new Error(JSON.stringify(fcm.body));
  const apns = await owner.post(`/api/environments/${envId}/resources`, {
    kind: "apns",
    name: "apple-push",
    keyId: KEY_ID,
    teamId: TEAM_ID,
    privateKey: apple.privateKey,
    upstreamUrl: upstream.url,
  });
  if (apns.status !== 201) throw new Error(JSON.stringify(apns.body));
  const vars: [string, string, string][] = [
    ["FIREBASE_SERVICE_ACCOUNT", fcm.body.data.id, "credentialsJson"],
    ["FIREBASE_PRIVATE_KEY", fcm.body.data.id, "privateKey"],
    ["APNS_KEY", apns.body.data.id, "key"],
    ["APNS_KEY_ID", apns.body.data.id, "keyId"],
    ["APNS_TEAM_ID", apns.body.data.id, "teamId"],
  ];
  for (const [key, resourceId, field] of vars)
    await owner.post(`/api/environments/${envId}/variables`, { type: "brokered", key, resourceId, field });
  const { token } = await loginDevice(app, owner);
  const boot = await cli(app, token).get(
    `/api/agent/bootstrap?projectId=${project.body.data.id}&env=development`,
  );
  return { token, envId, boot: boot.body.data, resources: { fcm: fcm.body.data, apns: apns.body.data } };
}

/** An HTTP/2 session to `host` through a Layer 2 tunnel, trusting only the org CA (as the preload does). */
function h2Through(token: string, envId: string, host: string, orgCaCert: string) {
  return http2.connect(`https://${host}`, {
    createConnection: () => {
      const url = new URL("/tunnel", base);
      url.protocol = "ws:";
      url.search = new URLSearchParams({ layer: "2", env: envId, host, port: "443" }).toString();
      const ws = new WebSocket(url, { headers: { authorization: `Bearer ${token}` } });
      return tls.connect({
        socket: createWebSocketStream(ws),
        servername: host,
        ca: orgCaCert,
        ALPNProtocols: ["h2"],
      });
    },
  });
}

function send(session: http2.ClientHttp2Session, headers: http2.OutgoingHttpHeaders, body?: string) {
  return new Promise<{ status: number; headers: http2.IncomingHttpHeaders; body: string }>(
    (resolve, reject) => {
      const stream = session.request({ ":method": "POST", ...headers });
      let out = "";
      let responseHeaders: http2.IncomingHttpHeaders = {};
      stream.on("response", (h) => {
        responseHeaders = h;
      });
      stream.on("data", (c: Buffer) => {
        out += c.toString();
      });
      stream.on("end", () =>
        resolve({ status: Number(responseHeaders[":status"]), headers: responseHeaders, body: out }),
      );
      stream.on("error", reject);
      stream.end(body);
    },
  );
}

describe("google-sa and apns adapters (§10.8, FR-CRY-004)", () => {
  it("S1 bootstrap holds only fake key material and real identifiers", async () => {
    const { boot, resources } = await scenario();
    const text = JSON.stringify(boot);
    expect(text).not.toContain(google.privateKey.split("\n")[1]);
    expect(text).not.toContain(apple.privateKey.split("\n")[1]);
    const sa = JSON.parse(boot.plain.FIREBASE_SERVICE_ACCOUNT);
    expect(sa.client_email).toBe(CLIENT_EMAIL);
    expect(sa.private_key).toBe(boot.plain.FIREBASE_PRIVATE_KEY);
    expect(boot.plain.APNS_KEY).toContain("BEGIN PRIVATE KEY");
    expect(boot.plain.APNS_KEY_ID).toBe(KEY_ID);
    expect(resources.fcm.config).not.toHaveProperty("privateKey");
    expect(boot.redirects.map((r: { host: string }) => r.host).sort()).toEqual([
      "api.push.apple.com",
      "api.sandbox.push.apple.com",
      "fcm.googleapis.com",
      "oauth2.googleapis.com",
    ]);
  });

  it("FCM: fake assertion → fake token → message sent with the real token, which never reaches the device", async () => {
    const { token, envId, boot } = await scenario();
    const fakeKey = boot.plain.FIREBASE_PRIVATE_KEY as string;
    const now = Math.floor(Date.now() / 1000);
    const assertion = signJwt("RS256", fakeKey, {
      iss: CLIENT_EMAIL,
      scope: "https://www.googleapis.com/auth/firebase.messaging",
      aud: "https://oauth2.googleapis.com/token",
      iat: now,
      exp: now + 3600,
    });
    const oauth = h2Through(token, envId, "oauth2.googleapis.com", boot.orgCaCert);
    const form = (a: string) =>
      new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
        assertion: a,
      }).toString();
    const exchanged = await send(
      oauth,
      { ":path": "/token", "content-type": "application/x-www-form-urlencoded" },
      form(assertion),
    );
    expect(exchanged.status).toBe(200);
    const fakeToken = JSON.parse(exchanged.body).access_token as string;
    expect(fakeToken).toMatch(/^ya29\.cb_/);
    expect(exchanged.body).not.toContain(REAL_ACCESS_TOKEN);

    // An assertion signed by any other key is refused at the gateway.
    const other = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey;
    const forged = await send(
      oauth,
      { ":path": "/token", "content-type": "application/x-www-form-urlencoded" },
      form(signJwt("RS256", other, { iss: CLIENT_EMAIL, iat: now, exp: now + 60 })),
    );
    expect(forged.status).toBe(400);
    oauth.close();

    const fcm = h2Through(token, envId, "fcm.googleapis.com", boot.orgCaCert);
    const message = JSON.stringify({ message: { token: "device-token-1", notification: { title: "hi" } } });
    const sent = await send(
      fcm,
      {
        ":path": "/v1/projects/cb-shop/messages:send",
        authorization: `Bearer ${fakeToken}`,
        "content-type": "application/json",
      },
      message,
    );
    expect(sent.status).toBe(200);
    expect(JSON.parse(sent.body).name).toBe("projects/cb-shop/messages/1");
    expect(sent.body).not.toContain(REAL_ACCESS_TOKEN);
    const unknown = await send(
      fcm,
      { ":path": "/v1/projects/cb-shop/messages:send", authorization: "Bearer ya29.cb_nope" },
      message,
    );
    expect(unknown.status).toBe(401);
    fcm.close();
    expect(
      upstream.seen.filter((s) => s.path.startsWith("/v1/")).every((s) => !s.authorization?.includes("cb_")),
    ).toBe(true);
  });

  it("APNs: provider JWT signed with the fake .p8 is re-signed with the real key; forged JWTs get InvalidProviderToken", async () => {
    const { token, envId, boot } = await scenario();
    const jwt = (key: string, kid = KEY_ID) =>
      signJwt("ES256", key, { iss: TEAM_ID, iat: Math.floor(Date.now() / 1000) }, { kid });
    const session = h2Through(token, envId, "api.sandbox.push.apple.com", boot.orgCaCert);
    const push = (bearer: string) =>
      send(
        session,
        {
          ":path": "/3/device/abcdef0123",
          authorization: `bearer ${bearer}`,
          "apns-topic": "dev.cp-test.app",
        },
        JSON.stringify({ aps: { alert: "hello" } }),
      );
    const ok = await push(jwt(boot.plain.APNS_KEY));
    expect(ok.status).toBe(200);
    expect(ok.headers["apns-id"]).toBe("11111111-2222-3333-4444-555555555555");
    const other = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;
    const forged = await push(jwt(other.export({ type: "pkcs8", format: "pem" }).toString()));
    expect(forged.status).toBe(403);
    expect(JSON.parse(forged.body).reason).toBe("InvalidProviderToken");
    session.close();
  });
});
