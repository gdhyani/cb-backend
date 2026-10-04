import type http from "node:http";
import type { AddressInfo } from "node:net";
import { CreateBucketCommand, GetObjectCommand, PutObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
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
const S3_ENDPOINT = "http://127.0.0.1:9010";
const S3_ACCESS_KEY = "shopadmin";

let backendDb: Awaited<ReturnType<typeof startMemoryMongo>>;
let server: http.Server;
let base: string;

describe.skipIf(!PASSWORD)("SQL, SMTP and AWS adapters through tunnels (§10.8)", () => {
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
    const s3 = await owner.post(`/api/environments/${envId}/resources`, {
      kind: "aws",
      name: "uploads",
      region: "us-east-1",
      endpoint: S3_ENDPOINT,
      accessKeyId: S3_ACCESS_KEY,
      secretAccessKey: PASSWORD,
    });
    if (s3.status !== 201) throw new Error(JSON.stringify(s3.body));
    const awsIds = { s3: s3.body.data.id as string };
    for (const [key, field] of [
      ["AWS_ACCESS_KEY_ID", "accessKeyId"],
      ["AWS_SECRET_ACCESS_KEY", "secretAccessKey"],
      ["AWS_ENDPOINT_URL", "endpoint"],
      ["AWS_REGION", "region"],
    ])
      await owner.post(`/api/environments/${envId}/variables`, {
        type: "brokered",
        key,
        resourceId: awsIds.s3,
        field,
      });
    const bob = await addMember(app, owner, orgId, "Bob");
    await owner.post(`/api/environments/${envId}/grants`, { userId: bob.userId });
    const { token } = await loginDevice(app, bob.member);
    const boot = await cli(app, token).get(
      `/api/agent/bootstrap?projectId=${project.body.data.id}&env=development`,
    );
    const envOf = (kind: string) =>
      boot.body.data.listeners.find((l: { kind: string }) => l.kind === kind).env as Record<string, string>;
    return { token, envId, ids: { ...ids, ...awsIds }, boot, envOf, owner, bob };
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

  it("S3 SDK put/get and presigned GET work with fake keys re-signed at the gateway", async () => {
    const { token, envId, ids, boot, envOf } = await scenario();
    const plain = boot.body.data.plain as Record<string, string>;
    expect(plain.AWS_ACCESS_KEY_ID).toMatch(/^AKIACB[A-Z2-7]{14}$/);
    expect(JSON.stringify(boot.body)).not.toContain(S3_ACCESS_KEY);
    const listener = await localListener(base, token, { layer: "1", env: envId, resource: ids.s3 });
    const client = (accessKeyId: string, secretAccessKey: string) =>
      new S3Client({
        region: plain.AWS_REGION,
        endpoint: fill(envOf("aws").AWS_ENDPOINT_URL ?? "", listener.port),
        forcePathStyle: true,
        credentials: { accessKeyId, secretAccessKey },
      });
    const s3 = client(plain.AWS_ACCESS_KEY_ID ?? "", plain.AWS_SECRET_ACCESS_KEY ?? "");
    const Bucket = `cb-it-${Date.now()}`;
    await s3.send(new CreateBucketCommand({ Bucket }));
    await s3.send(new PutObjectCommand({ Bucket, Key: "a.txt", Body: "through cb" }));
    const got = await s3.send(new GetObjectCommand({ Bucket, Key: "a.txt" }));
    expect(await got.Body?.transformToString()).toBe("through cb");
    const url = await getSignedUrl(s3, new GetObjectCommand({ Bucket, Key: "a.txt" }), { expiresIn: 60 });
    expect(url).not.toContain(S3_ACCESS_KEY);
    expect(await (await fetch(url)).text()).toBe("through cb");
    const forged = client("AKIACBAAAAAAAAAAAAAA", plain.AWS_SECRET_ACCESS_KEY ?? "");
    await expect(forged.send(new GetObjectCommand({ Bucket, Key: "a.txt" }))).rejects.toThrow();
    listener.close();
  });

  it("J2/J4 credential profiles: a readonly grant can read but not write; switching it back reconnects on default", async () => {
    const { token, envId, ids, envOf, owner, bob } = await scenario();
    // A read-only Postgres role, created with the admin connection (test setup only).
    const admin = new pg.Client({ connectionString: PG_URI });
    await admin.connect();
    await admin.query("CREATE TABLE IF NOT EXISTS cb_orders (id serial primary key, sku text)");
    await admin.query(
      `DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'cb_reader') THEN CREATE ROLE cb_reader LOGIN; END IF; END $$`,
    );
    await admin.query(`ALTER ROLE cb_reader PASSWORD '${(PASSWORD ?? "").replaceAll("'", "''")}'`);
    await admin.query("GRANT SELECT ON cb_orders TO cb_reader");
    await admin.end();

    const created = await owner.post(`/api/resources/${ids.pg}/profiles`, {
      name: "readonly",
      connectionUri: `postgresql://cb_reader:${enc}@127.0.0.1:5433/shop`,
    });
    expect(created.status).toBe(201);
    const listed = await owner.get(`/api/resources/${ids.pg}/profiles`);
    expect(listed.body.data.map((p: { name: string }) => p.name)).toEqual(["default", "readonly"]);
    expect(JSON.stringify(listed.body)).not.toContain(PASSWORD);
    expect(
      (await owner.post(`/api/resources/${ids.pg}/profiles`, { name: "default", connectionUri: PG_URI }))
        .status,
    ).toBe(400);

    const matrix = await owner.get(
      `/api/projects/${(await owner.get(`/api/environments/${envId}`)).body.data.projectId}/access`,
    );
    const grant = matrix.body.data.grants.find((g: { userId: string }) => g.userId === bob.userId);
    const missing = await owner.patch(`/api/grants/${grant.id}`, {
      resourceProfiles: [{ resourceId: ids.pg, profile: "nope" }],
    });
    expect(missing.status).toBe(400);
    const assigned = await owner.patch(`/api/grants/${grant.id}`, {
      resourceProfiles: [{ resourceId: ids.pg, profile: "readonly" }],
    });
    expect(assigned.body.data.resourceProfiles).toEqual([{ resourceId: ids.pg, profile: "readonly" }]);
    expect((await owner.delete(`/api/resources/${ids.pg}/profiles/readonly`)).status).toBe(409);

    const listener = await localListener(base, token, { layer: "1", env: envId, resource: ids.pg });
    const url = fill(envOf("postgres").DATABASE_URL ?? "", listener.port);
    const reader = new pg.Client({ connectionString: url });
    await reader.connect();
    expect((await reader.query("SELECT current_user AS u")).rows[0].u).toBe("cb_reader");
    await reader.query("SELECT count(*) FROM cb_orders");
    await expect(reader.query("INSERT INTO cb_orders (sku) VALUES ('nope')")).rejects.toThrow(
      /permission denied/,
    );

    // Back to default: the live readonly session is cut, the next connection writes as the admin user.
    const ended = new Promise((r) => reader.once("error", r).once("end", r));
    await owner.patch(`/api/grants/${grant.id}`, { resourceProfiles: [] });
    await ended;
    const writer = new pg.Client({ connectionString: url });
    await writer.connect();
    expect((await writer.query("SELECT current_user AS u")).rows[0].u).toBe("shop_admin");
    await writer.query("INSERT INTO cb_orders (sku) VALUES ('ok')");
    await writer.end();
    listener.close();
    expect((await owner.delete(`/api/resources/${ids.pg}/profiles/readonly`)).status).toBe(200);
  });
});
