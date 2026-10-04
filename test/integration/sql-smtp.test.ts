import type http from "node:http";
import type { AddressInfo } from "node:net";
import mongoose from "mongoose";
import mysql from "mysql2/promise";
import nodemailer from "nodemailer";
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

// Real services from docker-compose.test.yml; the password is supplied at run time, never stored in files.
const PASSWORD = process.env.CB_TEST_DB_PASSWORD;
const enc = encodeURIComponent(PASSWORD ?? "");
const PG_URI = `postgresql://shop_admin:${enc}@127.0.0.1:5433/shop`;
const MYSQL_URI = `mysql://shop_admin:${enc}@127.0.0.1:3307/shop`;
const SMTP_URI = `smtp://shop_mailer:${enc}@127.0.0.1:1026`;

let backendDb: Awaited<ReturnType<typeof startMemoryMongo>>;
let server: http.Server;
let base: string;

describe.skipIf(!PASSWORD)("SQL and SMTP adapters through tunnels (§10.8)", () => {
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

  async function scenario() {
    const app = server.listeners("request")[0] as never;
    const { owner, orgId } = await signupOwner(app);
    const project = await owner.post(`/api/orgs/${orgId}/projects`, { name: "Shop" });
    const envId = project.body.data.environments[0].id as string;
    const make = async (kind: string, name: string, connectionUri: string, vars: [string, string][]) => {
      const r = await owner.post(`/api/environments/${envId}/resources`, { kind, name, connectionUri });
      if (r.status !== 201) throw new Error(JSON.stringify(r.body));
      for (const [key, field] of vars)
        await owner.post(`/api/environments/${envId}/variables`, {
          type: "brokered",
          key,
          resourceId: r.body.data.id,
          field,
        });
      return r.body.data.id as string;
    };
    const ids = {
      pg: await make("postgres", "orders-db", PG_URI, [["DATABASE_URL", "url"]]),
      mysql: await make("mysql", "legacy-db", MYSQL_URI, [["MYSQL_URL", "url"]]),
      smtp: await make("smtp", "mailer", SMTP_URI, [
        ["SMTP_HOST", "host"],
        ["SMTP_PORT", "port"],
        ["SMTP_USER", "user"],
        ["SMTP_PASS", "password"],
      ]),
    };
    const bob = await addMember(app, owner, orgId, "Bob");
    await owner.post(`/api/environments/${envId}/grants`, { userId: bob.userId });
    const { token } = await loginDevice(app, bob.member);
    const boot = await cli(app, token).get(
      `/api/agent/bootstrap?projectId=${project.body.data.id}&env=development`,
    );
    const envOf = (kind: string) =>
      boot.body.data.listeners.find((l: { kind: string }) => l.kind === kind).env as Record<string, string>;
    return { token, envId, ids, boot, envOf };
  }

  const fill = (template: string, port: number) => template.replaceAll("{port}", String(port));

  it("S1 bootstrap carries only fake database and mail credentials", async () => {
    const { boot } = await scenario();
    expect(JSON.stringify(boot.body)).not.toContain(PASSWORD);
    const urls = boot.body.data.listeners.flatMap((l: { env: Record<string, string> }) =>
      Object.values(l.env),
    );
    expect(urls.join(" ")).toMatch(
      /postgresql:\/\/cbu_[a-z2-7]{8}:[A-Za-z0-9]{32}@127\.0\.0\.1:\{port\}\/shop\?sslmode=disable/,
    );
    expect(urls.join(" ")).toMatch(/mysql:\/\/cbu_[a-z2-7]{8}:[A-Za-z0-9]{32}@127\.0\.0\.1:\{port\}\/shop/);
  });

  it("T4 node-postgres works through the tunnel (SCRAM-SHA-256 upstream)", async () => {
    const { token, envId, ids, envOf } = await scenario();
    const listener = await localListener(base, token, { layer: "1", env: envId, resource: ids.pg });
    const client = new pg.Client({
      connectionString: fill(envOf("postgres").DATABASE_URL ?? "", listener.port),
    });
    await client.connect();
    await client.query("CREATE TABLE IF NOT EXISTS cb_orders (id serial primary key, sku text)");
    await client.query("INSERT INTO cb_orders (sku) VALUES ($1)", ["A-1"]);
    const res = await client.query("SELECT count(*)::int AS n FROM cb_orders WHERE sku = $1", ["A-1"]);
    expect(res.rows[0].n).toBeGreaterThanOrEqual(1);
    await client.end();
    const wrong = new pg.Client({
      connectionString: `postgresql://cbu_nope:wrong@127.0.0.1:${listener.port}/shop?sslmode=disable`,
    });
    await expect(wrong.connect()).rejects.toThrow(/password authentication failed/);
    listener.close();
  });

  it("T4 mysql2 works through the tunnel (caching_sha2_password upstream)", async () => {
    const { token, envId, ids, envOf } = await scenario();
    const listener = await localListener(base, token, { layer: "1", env: envId, resource: ids.mysql });
    const conn = await mysql.createConnection(fill(envOf("mysql").MYSQL_URL ?? "", listener.port));
    await conn.query(
      "CREATE TABLE IF NOT EXISTS cb_items (id int auto_increment primary key, name varchar(40))",
    );
    await conn.execute("INSERT INTO cb_items (name) VALUES (?)", ["widget"]);
    const [rows] = await conn.query("SELECT COUNT(*) AS n FROM cb_items");
    expect((rows as { n: number }[])[0]?.n).toBeGreaterThanOrEqual(1);
    await conn.end();
    await expect(
      mysql.createConnection(`mysql://cbu_nope:wrong@127.0.0.1:${listener.port}/shop`),
    ).rejects.toThrow(/Access denied/);
    listener.close();
  });

  it("nodemailer sends through the tunnel with fake SMTP credentials", async () => {
    const { token, envId, ids, envOf } = await scenario();
    const listener = await localListener(base, token, { layer: "1", env: envId, resource: ids.smtp });
    const env = envOf("smtp");
    const transport = nodemailer.createTransport({
      host: env.SMTP_HOST,
      port: Number(fill(env.SMTP_PORT ?? "", listener.port)),
      secure: false,
      auth: { user: env.SMTP_USER, pass: env.SMTP_PASS },
    });
    const subject = `cb test ${Date.now()}`;
    const info = await transport.sendMail({
      from: "shop@cp-test.dev",
      to: "dan@cp-test.dev",
      subject,
      text: "hello through cb",
    });
    expect(info.accepted).toEqual(["dan@cp-test.dev"]);
    const inbox = (await (await fetch("http://127.0.0.1:8026/api/v1/messages")).json()) as {
      messages: { Subject: string }[];
    };
    expect(inbox.messages.some((m) => m.Subject === subject)).toBe(true);
    const bad = nodemailer.createTransport({
      host: env.SMTP_HOST,
      port: listener.port,
      secure: false,
      auth: { user: "cbu_nope", pass: "wrong" },
    });
    await expect(bad.sendMail({ from: "a@b.c", to: "d@e.f", text: "x" })).rejects.toThrow(
      /Invalid login|535/,
    );
    listener.close();
  });
});
