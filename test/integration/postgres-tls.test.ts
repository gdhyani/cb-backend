import fs from "node:fs";
import type http from "node:http";
import type { AddressInfo } from "node:net";
import path from "node:path";
import mongoose from "mongoose";
import pg from "pg";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createApp } from "../../src/app.js";
import { connectMongo, disconnectMongo } from "../../src/clients/mongodb.client.js";
import { loadEnv, setEnv } from "../../src/config/env.js";
import { createServer } from "../../src/server.js";
import { localListener } from "../helpers/agent.js";
import { addMember, cli, loginDevice, signupOwner } from "../helpers/api.js";
import { testEnvVars } from "../helpers/env.js";
import { startMemoryMongo } from "../helpers/mongo.js";

// TLS-only Postgres from docker-compose.test.yml (postgres-tls) on the private CA from scripts/test-certs.sh.
// No global extra CA here: trust comes only from the resource's caCert. Password supplied at run time.
const PASSWORD = process.env.CB_TEST_DB_PASSWORD;
const CA_FILE = path.resolve(import.meta.dirname, "../../test-certs/ca.pem");
const enc = encodeURIComponent(PASSWORD ?? "");

let backendDb: Awaited<ReturnType<typeof startMemoryMongo>>;
let server: http.Server;
let base: string;

describe.skipIf(!PASSWORD || !fs.existsSync(CA_FILE))(
  "postgres TLS with a private CA (§10.8, FR-GW-004)",
  () => {
    beforeAll(async () => {
      backendDb = await startMemoryMongo();
      setEnv(loadEnv(testEnvVars(backendDb.uri)));
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

    async function scenario(sslmode: string) {
      const app = server.listeners("request")[0] as never;
      const { owner, orgId } = await signupOwner(app);
      const project = await owner.post(`/api/orgs/${orgId}/projects`, { name: "Shop" });
      const envId = project.body.data.environments[0].id as string;
      const r = await owner.post(`/api/environments/${envId}/resources`, {
        kind: "postgres",
        name: "tls-pg",
        connectionUri: `postgresql://shop_admin:${enc}@localhost:5435/shop?sslmode=${sslmode}`,
        caCert: fs.readFileSync(CA_FILE, "utf8"),
      });
      if (r.status !== 201) throw new Error(JSON.stringify(r.body));
      await owner.post(`/api/environments/${envId}/variables`, {
        type: "brokered",
        key: "DATABASE_URL",
        resourceId: r.body.data.id,
        field: "url",
      });
      const bob = await addMember(app, owner, orgId, "Bob");
      await owner.post(`/api/environments/${envId}/grants`, { userId: bob.userId });
      const { token } = await loginDevice(app, bob.member);
      const boot = await cli(app, token).get(
        `/api/agent/bootstrap?projectId=${project.body.data.id}&env=development`,
      );
      const url = boot.body.data.listeners.find((l: { kind: string }) => l.kind === "postgres").env
        .DATABASE_URL as string;
      const listener = await localListener(base, token, { layer: "1", env: envId, resource: r.body.data.id });
      return {
        owner,
        resourceId: r.body.data.id as string,
        url: url.replace("{port}", String(listener.port)),
        listener,
      };
    }

    it.each(["require", "verify-full"])(
      "FR-GW-004 node-postgres through the gateway (sslmode=%s, caCert)",
      async (mode) => {
        const { url, listener } = await scenario(mode);
        const client = new pg.Client({ connectionString: url });
        await client.connect();
        const { rows } = await client.query("SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()");
        await client.end();
        expect(rows[0]?.ssl).toBe(true);
        listener.close();
      },
    );

    it.each(["require", "verify-full"])(
      "FR-GW-004 test connection trusts the caCert (sslmode=%s in the stored URI)",
      async (mode) => {
        const { owner, resourceId, listener } = await scenario(mode);
        const res = await owner.post(`/api/resources/${resourceId}/test`, {});
        expect(res.body.data, JSON.stringify(res.body.data)).toMatchObject({ ok: true });
        listener.close();
      },
    );
  },
);
