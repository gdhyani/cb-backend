import type { Express } from "express";
import mongoose, { Types } from "mongoose";
import request from "supertest";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createApp } from "../../src/app.js";
import { connectMongo, disconnectMongo } from "../../src/clients/mongodb.client.js";
import { LOGIN_MAX_FAILURES_PER_EMAIL, LOGIN_MAX_FAILURES_PER_IP } from "../../src/constants.js";
import { UserModel } from "../../src/models/user.model.js";
import {
  clearLoginFailures,
  loginLimiterSize,
  recordLoginFailure,
} from "../../src/services/login-limit.service.js";
import { loadOrgCa } from "../../src/services/org-ca.service.js";
import { browser, cli, loginDevice, signupOwner } from "../helpers/api.js";
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
  clearLoginFailures();
});

const login = (email: string, password: string) => browser(app).post("/api/auth/login", { email, password });
/** signupOwner(app, suffix) creates ada<suffix>@example.com with this password (test/helpers/api.ts). */
async function owner(suffix = "") {
  await signupOwner(app, suffix);
  return { email: `ada${suffix}@example.com`, password: "correct-horse-battery" };
}

describe("S10 / FR-CRY-006 login protection", () => {
  it("S10 passwords are stored as argon2id", async () => {
    await signupOwner(app);
    const users = await UserModel.find().select("+passwordHash").lean();
    expect(users.length).toBeGreaterThan(0);
    for (const u of users) expect(u.passwordHash).toMatch(/^\$argon2id\$/);
  });

  it("S10 login is rate limited per email after repeated failures, even with the right password", async () => {
    const { email, password } = await owner();
    for (let i = 0; i < LOGIN_MAX_FAILURES_PER_EMAIL; i++)
      expect((await login(email, "wrong-password")).status).toBe(401);
    const blocked = await login(email, password);
    expect(blocked.status).toBe(429);
    expect(blocked.body).toMatchObject({ success: false, error: { code: "RATE_LIMITED", statusCode: 429 } });
    expect(Number(blocked.headers["retry-after"])).toBeGreaterThan(0);
    // The limit is per email: another account from the same address still logs in.
    const other = await owner("-other");
    expect((await login(other.email, other.password)).status).toBe(200);
  });

  it("S10 login is rate limited per IP across many emails", async () => {
    for (let i = 0; i < LOGIN_MAX_FAILURES_PER_IP; i++)
      expect((await login(`nobody-${i}@example.test`, "wrong-password")).status).toBe(401);
    const { email, password } = await owner();
    expect((await login(email, password)).status).toBe(429);
  });

  it("S10 a successful login clears that email's failures", async () => {
    const { email, password } = await owner();
    for (let i = 0; i < LOGIN_MAX_FAILURES_PER_EMAIL - 1; i++) await login(email, "wrong-password");
    expect((await login(email, password)).status).toBe(200);
    for (let i = 0; i < LOGIN_MAX_FAILURES_PER_EMAIL - 1; i++)
      expect((await login(email, "wrong-password")).status).toBe(401);
  });

  it("S10 a burst of parallel wrong-password logins for one email cannot exceed the limit", async () => {
    const { email } = await owner();
    const results = await Promise.all(
      Array.from({ length: 25 }, () =>
        request(app)
          .post("/api/auth/login")
          .set("x-cb-csrf", "1")
          .send({ email, password: "wrong-password" }),
      ),
    );
    const guesses = results.filter((r) => r.status === 401).length;
    expect(guesses).toBeLessThanOrEqual(LOGIN_MAX_FAILURES_PER_EMAIL);
    expect(results.filter((r) => r.status === 429).length).toBe(25 - guesses);
  });

  it("S10 behind the dashboard (a loopback proxy) the per-IP limit uses the forwarded browser address", async () => {
    const from = (ip: string, email: string, password: string) =>
      request(app)
        .post("/api/auth/login")
        .set("x-cb-csrf", "1")
        .set("x-forwarded-for", ip)
        .send({ email, password });
    for (let i = 0; i < LOGIN_MAX_FAILURES_PER_IP; i++)
      expect((await from("203.0.113.7", `nobody-${i}@example.test`, "wrong-password")).status).toBe(401);
    expect((await from("203.0.113.7", "nobody-x@example.test", "wrong-password")).status).toBe(429);
    // Someone else, logging in through the same dashboard, is not locked out by that address.
    const { email, password } = await owner();
    expect((await from("198.51.100.9", email, password)).status).toBe(200);
  });

  it("S10 the limiter's memory stays bounded however many emails and addresses are tried", () => {
    for (let i = 0; i < 25_000; i++)
      recordLoginFailure(`spray-${i}@example.test`, `2001:db8::${i.toString(16)}`);
    const size = loginLimiterSize();
    expect(size.emails).toBeLessThanOrEqual(10_000);
    expect(size.ips).toBeLessThanOrEqual(10_000);
  });

  it("S10 an unknown email and a wrong password look the same, so the limit does not reveal accounts", async () => {
    const { email } = await owner();
    const known = await login(email, "wrong-password");
    const unknown = await login("ghost@example.test", "wrong-password");
    expect(unknown.status).toBe(known.status);
    expect(unknown.body.error.code).toBe(known.body.error.code);
  });
});

describe("S5 org CA", () => {
  it("S5 the agent bootstrap carries the org CA certificate, never its private key", async () => {
    const { owner: admin, orgId } = await signupOwner(app);
    const project = await admin.post(`/api/orgs/${orgId}/projects`, { name: "Ca" });
    const { token } = await loginDevice(app, admin);
    const boot = await cli(app, token).get(
      `/api/agent/bootstrap?projectId=${project.body.data.id}&env=development`,
    );
    expect(boot.status).toBe(200);
    const ca = await loadOrgCa(new Types.ObjectId(orgId));
    expect(boot.body.data.orgCaCert).toBe(ca.certPem);
    const body = JSON.stringify(boot.body);
    const keyBody = ca.keyPem.split("\n").filter((l) => l && !l.startsWith("-----"));
    expect(keyBody.length).toBeGreaterThan(0);
    for (const line of keyBody) expect(body).not.toContain(line);
  });
});
