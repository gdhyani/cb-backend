import fs from "node:fs";
import type http from "node:http";
import type { AddressInfo } from "node:net";
import path from "node:path";
import mongoose from "mongoose";
import mysql from "mysql2/promise";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createApp } from "../../src/app.js";
import { connectMongo, disconnectMongo } from "../../src/clients/mongodb.client.js";
import { loadEnv, setEnv } from "../../src/config/env.js";
import { ResourceModel } from "../../src/models/resource.model.js";
import { createServer } from "../../src/server.js";
import { localListener } from "../helpers/agent.js";
import { addMember, cli, loginDevice, signupOwner } from "../helpers/api.js";
import { testEnvVars } from "../helpers/env.js";
import { startMemoryMongo } from "../helpers/mongo.js";

// TLS-only MySQL from docker-compose.test.yml (mysql-tls, require_secure_transport) with certificates from
// scripts/test-certs.sh. The password is supplied at run time, never stored in files.
const PASSWORD = process.env.CB_TEST_DB_PASSWORD;
const CA_FILE = path.resolve(import.meta.dirname, "../../test-certs/ca.pem");
const enc = encodeURIComponent(PASSWORD ?? "");
const TLS_URI = (query: string) => `mysql://shop_admin:${enc}@localhost:3309/shop${query}`;

let backendDb: Awaited<ReturnType<typeof startMemoryMongo>>;
let server: http.Server;
let base: string;

describe.skipIf(!PASSWORD || !fs.existsSync(CA_FILE))("mysql upstream TLS (§10.8, FR-GW-004)", () => {
  beforeAll(async () => {
    backendDb = await startMemoryMongo();
    setEnv(loadEnv({ ...testEnvVars(backendDb.uri), UPSTREAM_EXTRA_CA_FILE: CA_FILE }));
    await connectMongo(backendDb.uri);
    server = createServer(createApp()).server;
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  }, 120_000);
  afterAll(async () => {
    server?.closeAllConnections();
    server?.close();
    await disconnectMongo();
    await backendDb?.stop();
  });
  beforeEach(async () => {
    await mongoose.connection.db?.dropDatabase();
  });

  async function scenario(connectionUri: string, extra: Record<string, unknown> = {}) {
    const app = server.listeners("request")[0] as never;
    const { owner, orgId } = await signupOwner(app);
    const project = await owner.post(`/api/orgs/${orgId}/projects`, { name: "Shop" });
    const envId = project.body.data.environments[0].id as string;
    const r = await owner.post(`/api/environments/${envId}/resources`, {
      kind: "mysql",
      name: "tls-db",
      connectionUri,
      ...extra,
    });
    if (r.status !== 201) throw new Error(JSON.stringify(r.body));
    await owner.post(`/api/environments/${envId}/variables`, {
      type: "brokered",
      key: "MYSQL_URL",
      resourceId: r.body.data.id,
      field: "url",
    });
    const bob = await addMember(app, owner, orgId, "Bob");
    await owner.post(`/api/environments/${envId}/grants`, { userId: bob.userId });
    const { token } = await loginDevice(app, bob.member);
    const boot = await cli(app, token).get(
      `/api/agent/bootstrap?projectId=${project.body.data.id}&env=development`,
    );
    const url = boot.body.data.listeners.find((l: { kind: string }) => l.kind === "mysql").env
      .MYSQL_URL as string;
    const listener = await localListener(base, token, { layer: "1", env: envId, resource: r.body.data.id });
    return {
      url: url.replace("{port}", String(listener.port)),
      listener,
      owner,
      envId,
      resourceId: r.body.data.id,
    };
  }

  it.each(["?ssl=true", "?ssl-mode=REQUIRED", "?sslmode=verify-full"])(
    "FR-GW-004 mysql2 works against a TLS-only server when the stored URI asks for TLS (%s)",
    async (query) => {
      const { url, listener } = await scenario(TLS_URI(query));
      const conn = await mysql.createConnection(url);
      const [rows] = await conn.query("SHOW STATUS LIKE 'Ssl_cipher'");
      await conn.end();
      // The gateway's upstream session is encrypted (the app ↔ listener hop stays local and plain).
      expect((rows as { Value: string }[])[0]?.Value).not.toBe("");
      listener.close();
    },
  );

  it("FR-GW-004 an untrusted server certificate is refused (verification is never skipped)", async () => {
    setEnv(loadEnv(testEnvVars(backendDb.uri))); // no extra CA: the test CA is unknown
    try {
      const { url, listener } = await scenario(TLS_URI("?ssl=true"));
      await expect(mysql.createConnection(url)).rejects.toThrow(
        /could not verify the database's TLS certificate/,
      );
      listener.close();
    } finally {
      setEnv(loadEnv({ ...testEnvVars(backendDb.uri), UPSTREAM_EXTRA_CA_FILE: CA_FILE }));
    }
  });

  it("test connection honours ?ssl=true in the URI even when an older stored config says tls:false", async () => {
    const { owner, resourceId, listener } = await scenario(TLS_URI("?ssl=true"));
    // Services saved before ?ssl=true was recognised kept tls:false (cp-test MYSQL_URL_LOCAL_TLS).
    await ResourceModel.updateOne({ _id: resourceId }, { $set: { "config.tls": false } });
    const res = await owner.post(`/api/resources/${resourceId}/test`, {});
    expect(res.body.data).toMatchObject({ ok: true });
    listener.close();
  });

  it("a TLS-only server without ?ssl in the stored URI explains the fix in the test-connection result", async () => {
    const { owner, resourceId, listener } = await scenario(TLS_URI(""));
    const res = await owner.post(`/api/resources/${resourceId}/test`, {});
    expect(JSON.stringify(res.body)).toMatch(/TLS|ssl=true/);
    expect(JSON.stringify(res.body)).not.toContain(PASSWORD ?? "unset");
    listener.close();
  });

  describe("per-resource CA certificate (self-hosted / private-CA clouds, production-safe)", () => {
    const noExtraCa = () => setEnv(loadEnv(testEnvVars(backendDb.uri)));
    const restore = () => setEnv(loadEnv({ ...testEnvVars(backendDb.uri), UPSTREAM_EXTRA_CA_FILE: CA_FILE }));

    it("FR-GW-004 a private-CA server is trusted through the resource's caCert, with no global extra CA", async () => {
      noExtraCa();
      try {
        const { url, listener } = await scenario(TLS_URI("?ssl=true"), {
          caCert: fs.readFileSync(CA_FILE, "utf8"),
        });
        const conn = await mysql.createConnection(url);
        const [rows] = await conn.query("SHOW STATUS LIKE 'Ssl_cipher'");
        await conn.end();
        expect((rows as { Value: string }[])[0]?.Value).not.toBe("");
        listener.close();
      } finally {
        restore();
      }
    });

    it("FR-GW-004 test connection also trusts the resource's caCert", async () => {
      noExtraCa();
      try {
        const { owner, resourceId, listener } = await scenario(TLS_URI("?ssl=true"), {
          caCert: fs.readFileSync(CA_FILE, "utf8"),
        });
        const res = await owner.post(`/api/resources/${resourceId}/test`, {});
        expect(res.body.data).toMatchObject({ ok: true });
        listener.close();
      } finally {
        restore();
      }
    });

    it("rejects a caCert that is not a PEM certificate", async () => {
      const app = server.listeners("request")[0] as never;
      const { owner, orgId } = await signupOwner(app);
      const project = await owner.post(`/api/orgs/${orgId}/projects`, { name: "Shop" });
      const envId = project.body.data.environments[0].id as string;
      const res = await owner.post(`/api/environments/${envId}/resources`, {
        kind: "mysql",
        name: "bad-ca",
        connectionUri: TLS_URI("?ssl=true"),
        caCert: "-----BEGIN CERTIFICATE-----\nnot a cert\n-----END CERTIFICATE-----",
      });
      expect(res.status).toBe(400);
      expect(JSON.stringify(res.body)).toMatch(/caCert/);
    });
  });
});
