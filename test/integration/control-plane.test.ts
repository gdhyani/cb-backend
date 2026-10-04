import type { Express } from "express";
import mongoose from "mongoose";
import request from "supertest";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createApp } from "../../src/app.js";
import { connectMongo, disconnectMongo } from "../../src/clients/mongodb.client.js";
import { type BusEvent, bus } from "../../src/events/bus.js";
import { GrantModel } from "../../src/models/grant.model.js";
import { ResourceModel } from "../../src/models/resource.model.js";
import { sweepExpiredGrants } from "../../src/services/grant.service.js";
import { addMember, browser, cli, loginDevice, signupOwner } from "../helpers/api.js";
import { useTestEnv } from "../helpers/env.js";
import { startMemoryMongo } from "../helpers/mongo.js";

let mongo: Awaited<ReturnType<typeof startMemoryMongo>>;
let app: Express;
const REAL_MONGO = "mongodb://admin:SUPER_SECRET_PW@db.internal:27017/shop?authSource=admin";

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

function captureBus(): BusEvent[] {
  const events: BusEvent[] = [];
  bus.subscribe((e) => events.push(e));
  return events;
}

describe("auth (J1, FR-AUTH-001)", () => {
  it("J1 signup creates the user, an org with them as owner, and a session", async () => {
    const owner = browser(app);
    const res = await owner.post("/api/auth/signup", {
      name: "Ada",
      email: "Ada@Example.com",
      password: "correct-horse-battery",
      orgName: "Acme",
    });
    expect(res.status).toBe(201);
    expect(res.body.data.user).toMatchObject({ name: "Ada", email: "ada@example.com" });
    expect(res.body.data.memberships).toEqual([
      { orgId: expect.any(String), orgName: "Acme", role: "owner" },
    ]);
    expect(res.headers["set-cookie"]?.[0]).toMatch(/cb_session=.*HttpOnly.*SameSite=Lax/i);
    expect((await owner.get("/api/auth/me")).body.data.user.email).toBe("ada@example.com");
    expect(JSON.stringify(res.body)).not.toContain("correct-horse-battery");
  });

  it("rejects duplicate emails, wrong passwords and missing CSRF headers", async () => {
    const { owner } = await signupOwner(app);
    const dup = await browser(app).post("/api/auth/signup", {
      name: "X",
      email: "ada@example.com",
      password: "correct-horse-battery",
      orgName: "Y",
    });
    expect(dup.body.error.code).toBe("EMAIL_TAKEN");
    const bad = await request(app)
      .post("/api/auth/login")
      .send({ email: "ada@example.com", password: "nope-nope-nope" });
    expect(bad.status).toBe(401);
    expect(bad.body.error.code).toBe("INVALID_CREDENTIALS");
    const noCsrf = await owner.raw.post("/api/orgs/000000000000000000000000/projects").send({ name: "p" });
    expect(noCsrf.body.error.code).toBe("CSRF_REQUIRED");
    expect((await request(app).get("/api/auth/me")).status).toBe(401);
  });

  it("logout ends the session", async () => {
    const { owner } = await signupOwner(app);
    await owner.post("/api/auth/logout");
    expect((await owner.get("/api/auth/me")).status).toBe(401);
  });
});

describe("organizations, invites and roles (J4, FR-UI-004)", () => {
  it("J4 invites a developer who can read projects but not manage them", async () => {
    const { owner, orgId } = await signupOwner(app);
    const { member } = await addMember(app, owner, orgId, "Bob");
    const members = await owner.get(`/api/orgs/${orgId}/members`);
    expect(members.body.data.map((m: { name: string; role: string }) => [m.name, m.role])).toEqual([
      ["Ada", "owner"],
      ["Bob", "developer"],
    ]);
    await owner.post(`/api/orgs/${orgId}/projects`, { name: "Shop API" });
    expect((await member.get(`/api/orgs/${orgId}/projects`)).body.data).toHaveLength(1);
    const forbidden = await member.post(`/api/orgs/${orgId}/projects`, { name: "Nope" });
    expect(forbidden.status).toBe(403);
    expect(forbidden.body.error.code).toBe("FORBIDDEN");
  });

  it("FR-AUTH-001 accepting an invite with a session cookie requires the CSRF header", async () => {
    const { owner, orgId } = await signupOwner(app);
    const invite = await owner.post(`/api/orgs/${orgId}/invites`, { role: "developer" });
    const other = await signupOwner(app, "2");
    const body = { token: invite.body.data.token };
    const withoutHeader = await other.owner.raw.post("/api/auth/accept-invite").send(body);
    expect(withoutHeader.status).toBe(403);
    expect(withoutHeader.body.error.code).toBe("CSRF_REQUIRED");
    expect((await other.owner.post("/api/auth/accept-invite", body)).status).toBe(200);
  });

  it("invite links are single-use and preview without auth", async () => {
    const { owner, orgId } = await signupOwner(app);
    const invite = await owner.post(`/api/orgs/${orgId}/invites`, { role: "admin" });
    expect(invite.body.data.url).toBe(`http://localhost:4201/invite/${invite.body.data.token}`);
    expect((await request(app).get(`/api/invites/${invite.body.data.token}`)).body.data).toMatchObject({
      orgName: "Acme",
      role: "admin",
    });
    await browser(app).post("/api/auth/accept-invite", {
      token: invite.body.data.token,
      name: "C",
      email: "c@example.com",
      password: "correct-horse-battery",
    });
    const again = await browser(app).post("/api/auth/accept-invite", {
      token: invite.body.data.token,
      name: "D",
      email: "d@example.com",
      password: "correct-horse-battery",
    });
    expect(again.status).toBe(410);
    expect(again.body.error.code).toBe("INVITE_INVALID");
  });

  it("protects the last owner and lets admins change roles and remove members", async () => {
    const { owner, orgId, userId } = await signupOwner(app);
    const { userId: bobId } = await addMember(app, owner, orgId, "Bob");
    expect(
      (await owner.patch(`/api/orgs/${orgId}/members/${userId}`, { role: "admin" })).body.error.code,
    ).toBe("LAST_OWNER");
    expect((await owner.patch(`/api/orgs/${orgId}/members/${bobId}`, { role: "admin" })).body.data.role).toBe(
      "admin",
    );
    expect((await owner.delete(`/api/orgs/${orgId}/members/${bobId}`)).status).toBe(200);
    expect((await owner.get(`/api/orgs/${orgId}/members`)).body.data).toHaveLength(1);
  });

  it("hides organizations from non-members", async () => {
    const { orgId } = await signupOwner(app);
    const { owner: other } = await signupOwner(app, "2");
    expect((await other.get(`/api/orgs/${orgId}/projects`)).status).toBe(404);
  });
});

describe("projects, resources and variables (J2, J3, L15)", () => {
  async function setup() {
    const ctx = await signupOwner(app);
    const project = await ctx.owner.post(`/api/orgs/${ctx.orgId}/projects`, { name: "Shop API" });
    const env = project.body.data.environments.find((e: { name: string }) => e.name === "development");
    return { ...ctx, project: project.body.data, envId: env.id as string };
  }

  it("J1 creates development and staging environments by default", async () => {
    const { project } = await setup();
    expect(project.slug).toBe("shop-api");
    expect(project.environments.map((e: { name: string }) => e.name)).toEqual(["development", "staging"]);
  });

  it("L15 S2 resource credentials are write-only and encrypted at rest", async () => {
    const { owner, envId } = await setup();
    const created = await owner.post(`/api/environments/${envId}/resources`, {
      kind: "mongodb",
      name: "main-db",
      connectionUri: REAL_MONGO,
    });
    expect(created.status).toBe(201);
    expect(created.body.data).toMatchObject({
      kind: "mongodb",
      credentialsSet: true,
      config: { host: "db.internal:27017", database: "shop" },
    });
    const list = await owner.get(`/api/environments/${envId}/resources`);
    for (const body of [created.body, list.body])
      expect(JSON.stringify(body)).not.toContain("SUPER_SECRET_PW");
    const raw = await ResourceModel.findOne().select("+credentials").lean();
    expect(JSON.stringify(raw)).not.toContain("SUPER_SECRET_PW");
  });

  it("validates connection URIs with field details", async () => {
    const { owner, envId } = await setup();
    const res = await owner.post(`/api/environments/${envId}/resources`, {
      kind: "redis",
      name: "cache",
      connectionUri: "http://nope",
    });
    expect(res.status).toBe(400);
    expect(res.body.error.details[0].path).toBe("connectionUri");
  });

  it("J3 supports plain, generated, visible and brokered variables and a developer preview", async () => {
    const { owner, orgId, envId } = await setup();
    const { userId: bobId } = await addMember(app, owner, orgId, "Bob");
    const db = await owner.post(`/api/environments/${envId}/resources`, {
      kind: "mongodb",
      name: "main-db",
      connectionUri: REAL_MONGO,
    });
    const vars = [
      { type: "plain", key: "PORT", value: "3000" },
      { type: "generated", key: "SESSION_SECRET", format: "hex:32" },
      { type: "visible", key: "LEGACY_TOKEN", value: "VISIBLE_REAL_VALUE" },
      { type: "brokered", key: "MONGODB_URI", resourceId: db.body.data.id, field: "url" },
    ];
    for (const v of vars)
      expect((await owner.post(`/api/environments/${envId}/variables`, v)).status).toBe(201);
    const bad = await owner.post(`/api/environments/${envId}/variables`, {
      type: "brokered",
      key: "X",
      resourceId: db.body.data.id,
      field: "key",
    });
    expect(bad.body.error.details[0].path).toBe("field");
    const list = await owner.get(`/api/environments/${envId}/variables`);
    expect(list.body.data.map((v: { key: string; type: string }) => `${v.key}:${v.type}`)).toEqual([
      "LEGACY_TOKEN:visible",
      "MONGODB_URI:brokered",
      "PORT:plain",
      "SESSION_SECRET:generated",
    ]);
    expect(JSON.stringify(list.body)).not.toContain("VISIBLE_REAL_VALUE");
    const preview = await owner.get(`/api/environments/${envId}/preview?userId=${bobId}`);
    expect(preview.body.data.hasAccess).toBe(false);
    const byKey = Object.fromEntries(
      preview.body.data.entries.map((e: { key: string; display: string }) => [e.key, e.display]),
    );
    expect(byKey.PORT).toBe("3000");
    expect(byKey.SESSION_SECRET).toMatch(/^[0-9a-f]{32}$/);
    expect(byKey.MONGODB_URI).toContain("main-db");
    expect(JSON.stringify(preview.body)).not.toContain("VISIBLE_REAL_VALUE");
    expect(JSON.stringify(preview.body)).not.toContain("SUPER_SECRET_PW");
  });

  it("FR-EVT-001 variable changes publish config.changed", async () => {
    const { owner, envId } = await setup();
    const events = captureBus();
    await owner.post(`/api/environments/${envId}/variables`, { type: "plain", key: "A", value: "1" });
    expect(events).toContainEqual({ type: "config.changed", environmentId: envId });
  });
});

describe("access grants (J4, J7)", () => {
  async function setup() {
    const ctx = await signupOwner(app);
    const project = await ctx.owner.post(`/api/orgs/${ctx.orgId}/projects`, { name: "Shop API" });
    const env = project.body.data.environments[0];
    const bob = await addMember(app, ctx.owner, ctx.orgId, "Bob");
    return { ...ctx, projectId: project.body.data.id as string, envId: env.id as string, bob };
  }

  it("J4 grants (with expiry) appear in the access matrix and on the developer's project list", async () => {
    const { owner, orgId, projectId, envId, bob } = await setup();
    const expiresAt = new Date(Date.now() + 3_600_000).toISOString();
    const grant = await owner.post(`/api/environments/${envId}/grants`, { userId: bob.userId, expiresAt });
    expect(grant.status).toBe(201);
    const matrix = await owner.get(`/api/projects/${projectId}/access`);
    expect(matrix.body.data.grants).toEqual([
      expect.objectContaining({ userId: bob.userId, environmentId: envId, expiresAt }),
    ]);
    const bobView = await bob.member.get(`/api/orgs/${orgId}/projects`);
    expect(bobView.body.data[0].environments.find((e: { id: string }) => e.id === envId).hasAccess).toBe(
      true,
    );
    expect((await bob.member.get(`/api/projects/${projectId}/access`)).status).toBe(403);
  });

  it("J7 revoking publishes access.revoked and removes access", async () => {
    const { owner, orgId, envId, bob } = await setup();
    const grant = await owner.post(`/api/environments/${envId}/grants`, { userId: bob.userId });
    const events = captureBus();
    expect((await owner.delete(`/api/grants/${grant.body.data.id}`)).status).toBe(200);
    expect(events).toContainEqual(
      expect.objectContaining({
        type: "access.revoked",
        scope: "grant",
        environmentId: envId,
        userId: bob.userId,
      }),
    );
    const bobView = await bob.member.get(`/api/orgs/${orgId}/projects`);
    expect(bobView.body.data[0].environments[0].hasAccess).toBe(false);
  });

  it("temporary grants expire and are announced exactly once", async () => {
    const { owner, envId, bob } = await setup();
    await owner.post(`/api/environments/${envId}/grants`, {
      userId: bob.userId,
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    });
    await GrantModel.updateMany({}, { expiresAt: new Date(Date.now() - 1000) });
    const events = captureBus();
    expect(await sweepExpiredGrants()).toBe(1);
    expect(await sweepExpiredGrants()).toBe(0);
    expect(events.filter((e) => e.type === "access.revoked")).toHaveLength(1);
  });

  it("J7 the environment kill switch needs a reason and publishes access.revoked", async () => {
    const { owner, envId } = await setup();
    expect((await owner.patch(`/api/environments/${envId}`, { killed: true })).status).toBe(400);
    const events = captureBus();
    const killed = await owner.patch(`/api/environments/${envId}`, {
      killed: true,
      reason: "suspected leak",
    });
    expect(killed.body.data).toMatchObject({ killed: true, killedReason: "suspected leak" });
    expect(events).toContainEqual(
      expect.objectContaining({ type: "access.revoked", scope: "environment", environmentId: envId }),
    );
  });
});

describe("CLI device login (FR-AUTH-002, J5)", () => {
  it("J5 device-code flow: pending → approved in dashboard → token works for the API", async () => {
    const { owner, orgId } = await signupOwner(app);
    const start = await request(app)
      .post("/api/cli/device/start")
      .send({ deviceName: "ada-mbp", os: "darwin" });
    expect(start.body.data).toMatchObject({
      userCode: expect.stringMatching(/^[A-Z2-9]{4}-[A-Z2-9]{4}$/),
      interval: 2,
    });
    expect(start.body.data.verificationUrl).toBe(
      `http://localhost:4201/device?code=${start.body.data.userCode}`,
    );
    const pending = await request(app)
      .post("/api/cli/device/token")
      .send({ deviceCode: start.body.data.deviceCode });
    expect(pending.body.error.code).toBe("DEVICE_AUTH_PENDING");
    expect(
      (await owner.post("/api/cli/device/approve", { userCode: start.body.data.userCode.toLowerCase() }))
        .status,
    ).toBe(200);
    const token = await request(app)
      .post("/api/cli/device/token")
      .send({ deviceCode: start.body.data.deviceCode });
    expect(token.body.data.accessToken.split(".")).toHaveLength(3);
    expect(token.body.data.refreshToken).toMatch(/^cbr_/);
    const reuse = await request(app)
      .post("/api/cli/device/token")
      .send({ deviceCode: start.body.data.deviceCode });
    expect(reuse.status).toBe(404);
    const client = cli(app, token.body.data.accessToken);
    expect((await client.get("/api/cli/whoami")).body.data.user.email).toBe("ada@example.com");
    expect((await client.get(`/api/orgs/${orgId}/projects`)).status).toBe(200);
  });

  it("bearer-authenticated requests do not need the CSRF header; revoked devices are rejected", async () => {
    const { owner, orgId } = await signupOwner(app);
    const { token, deviceId } = await loginDevice(app, owner);
    expect((await cli(app, token).post(`/api/orgs/${orgId}/projects`, { name: "From CLI" })).status).toBe(
      201,
    );
    const events = captureBus();
    expect((await owner.delete(`/api/devices/${deviceId}`)).status).toBe(200);
    expect(events).toContainEqual(
      expect.objectContaining({ type: "access.revoked", scope: "device", deviceId }),
    );
    expect((await cli(app, token).get("/api/cli/whoami")).status).toBe(401);
  });

  it("admins see member devices; audit records the journey", async () => {
    const { owner, orgId } = await signupOwner(app);
    const bob = await addMember(app, owner, orgId, "Bob");
    await loginDevice(app, bob.member, "bob-laptop");
    const devices = await owner.get(`/api/orgs/${orgId}/devices`);
    expect(
      devices.body.data.map((d: { name: string; user: { name: string } }) => `${d.user.name}:${d.name}`),
    ).toEqual(["Bob:bob-laptop"]);
    const audit = await owner.get(`/api/orgs/${orgId}/audit?pageSize=50`);
    expect(audit.body.meta.pagination.total).toBeGreaterThanOrEqual(3);
    expect(audit.body.data.map((a: { action: string }) => a.action)).toEqual(
      expect.arrayContaining(["org.created", "member.invited", "member.joined", "device.approved"]),
    );
  });
});

describe("org stats (dashboard charts)", () => {
  it("returns 14 days of activity, resources by kind and grant mix; developers only see their own activity", async () => {
    const { owner, orgId } = await signupOwner(app);
    const project = await owner.post(`/api/orgs/${orgId}/projects`, { name: "Charts" });
    const envId = project.body.data.environments[0].id as string;
    await owner.post(`/api/environments/${envId}/resources`, {
      kind: "redis",
      name: "cache",
      connectionUri: "redis://:pw-1234@127.0.0.1:6390",
    });
    const dev = await addMember(app, owner, orgId, "Dev");
    await owner.post(`/api/environments/${envId}/grants`, {
      userId: dev.userId,
      expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
    });

    const stats = await owner.get(`/api/orgs/${orgId}/stats`);
    expect(stats.status).toBe(200);
    expect(stats.body.data.scope).toBe("org");
    expect(stats.body.data.days).toHaveLength(14);
    expect(stats.body.data.days.at(-1).byCategory.config).toBeGreaterThan(0);
    expect(stats.body.data.resourcesByKind).toEqual([{ kind: "redis", count: 1 }]);
    expect(stats.body.data.grants).toEqual({ permanent: 0, temporary: 1 });
    expect(stats.body.data.connectionsByProject[0]).toMatchObject({ name: "Charts", connections: 0 });

    const mine = await dev.member.get(`/api/orgs/${orgId}/stats`);
    expect(mine.body.data.scope).toBe("me");
    expect(mine.body.data.days.at(-1).byCategory.config).toBe(0);
  });
});

describe("project access (J4: project-wide or per-environment)", () => {
  it("J4 project-wide access covers environments created later; narrowing and removal revoke the rest", async () => {
    const { owner, orgId } = await signupOwner(app);
    const project = await owner.post(`/api/orgs/${orgId}/projects`, { name: "Payments" });
    const projectId = project.body.data.id as string;
    const devEnvId = project.body.data.environments[0].id as string;
    const dev = await addMember(app, owner, orgId, "Dana");
    const { token } = await loginDevice(app, dev.member);
    const boot = (env: string) =>
      cli(app, token).get(`/api/agent/bootstrap?projectId=${projectId}&env=${env}`);
    const events: BusEvent[] = [];
    const stop = bus.subscribe((e) => events.push(e));

    const granted = await owner.put(`/api/projects/${projectId}/access/${dev.userId}`, { scope: "project" });
    expect(granted.status).toBe(200);
    expect(granted.body.data).toEqual([expect.objectContaining({ scope: "project", environmentId: null })]);
    expect((await boot("development")).status).toBe(200);

    // A new environment is covered without another grant.
    const preview = await owner.post(`/api/projects/${projectId}/environments`, { name: "preview" });
    expect(preview.status).toBe(201);
    expect((await boot("preview")).status).toBe(200);

    // Narrow to development only: the project grant is revoked (and announced), preview is refused.
    const narrowed = await owner.put(`/api/projects/${projectId}/access/${dev.userId}`, {
      scope: "environments",
      environmentIds: [devEnvId],
    });
    expect(narrowed.body.data).toEqual([
      expect.objectContaining({ scope: "environment", environmentId: devEnvId }),
    ]);
    expect(events.some((e) => e.type === "access.revoked" && e.scope === "project")).toBe(true);
    expect((await boot("preview")).status).toBe(403);
    expect((await boot("development")).status).toBe(200);

    const access = await owner.get(`/api/orgs/${orgId}/members/${dev.userId}/access`);
    expect(access.body.data.projects).toEqual([
      expect.objectContaining({
        projectName: "Payments",
        grants: [expect.objectContaining({ scope: "environment", environmentName: "development" })],
      }),
    ]);

    expect((await owner.delete(`/api/projects/${projectId}/access/${dev.userId}`)).body.data).toEqual({
      revoked: 1,
    });
    expect((await boot("development")).status).toBe(403);
    stop();
  });

  it("J4 rejects grants for owners/admins, empty environment lists and foreign environments", async () => {
    const { owner, orgId, userId: ownerId } = await signupOwner(app);
    const project = await owner.post(`/api/orgs/${orgId}/projects`, { name: "Shop" });
    const other = await owner.post(`/api/orgs/${orgId}/projects`, { name: "Other" });
    const projectId = project.body.data.id as string;
    const dev = await addMember(app, owner, orgId, "Eli");
    expect(
      (await owner.put(`/api/projects/${projectId}/access/${ownerId}`, { scope: "project" })).status,
    ).toBe(400);
    expect(
      (
        await owner.put(`/api/projects/${projectId}/access/${dev.userId}`, {
          scope: "environments",
          environmentIds: [],
        })
      ).status,
    ).toBe(400);
    const foreign = other.body.data.environments[0].id as string;
    expect(
      (
        await owner.put(`/api/projects/${projectId}/access/${dev.userId}`, {
          scope: "environments",
          environmentIds: [foreign],
        })
      ).status,
    ).toBe(400);
  });
});

describe("presets (§10.8)", () => {
  it("serves provider presets as data, each with a valid kind and suggested variables", async () => {
    const { owner } = await signupOwner(app);
    const res = await owner.get("/api/presets");
    expect(res.status).toBe(200);
    const ids = res.body.data.map((p: { id: string }) => p.id);
    expect(ids).toEqual(
      expect.arrayContaining(["openai", "anthropic", "stripe", "razorpay", "firebase", "aws-s3"]),
    );
    const stripe = res.body.data.find((p: { id: string }) => p.id === "stripe");
    expect(stripe).toMatchObject({ kind: "http", defaults: { redirectHosts: ["api.stripe.com:443"] } });
    expect(stripe.variables).toEqual([{ key: "STRIPE_SECRET_KEY", field: "key" }]);
    expect((await request(app).get("/api/presets")).status).toBe(401);
  });
});

describe("kill switches, sessions and heartbeat (J7, FR-UI-002)", () => {
  it("J7 a device kill switch refuses bootstrap until cleared; an org switch stops even owners", async () => {
    const { owner, orgId } = await signupOwner(app);
    const project = await owner.post(`/api/orgs/${orgId}/projects`, { name: "Kill" });
    const projectId = project.body.data.id as string;
    const dev = await addMember(app, owner, orgId, "Kim");
    await owner.put(`/api/projects/${projectId}/access/${dev.userId}`, { scope: "project" });
    const { token, deviceId } = await loginDevice(app, dev.member);
    const boot = () => cli(app, token).get(`/api/agent/bootstrap?projectId=${projectId}&env=development`);
    expect((await boot()).status).toBe(200);

    const events: BusEvent[] = [];
    const stop = bus.subscribe((e) => events.push(e));
    expect((await owner.post(`/api/orgs/${orgId}/killswitches`, { scope: "device" })).status).toBe(400); // no target
    expect(
      (await owner.post(`/api/orgs/${orgId}/killswitches`, { scope: "device", targetId: deviceId })).status,
    ).toBe(400); // no reason
    const kill = await owner.post(`/api/orgs/${orgId}/killswitches`, {
      scope: "device",
      targetId: deviceId,
      reason: "laptop reported stolen",
    });
    expect(kill.status).toBe(201);
    expect(kill.body.data).toMatchObject({
      scope: "device",
      targetLabel: expect.any(String),
      clearedAt: null,
    });
    expect(events.some((e) => e.type === "access.revoked" && e.scope === "device")).toBe(true);
    const refused = await boot();
    expect(refused.status).toBe(403);
    expect(refused.body.error.code).toBe("KILLSWITCH_ACTIVE");
    expect(
      (
        await owner.post(`/api/orgs/${orgId}/killswitches`, {
          scope: "device",
          targetId: deviceId,
          reason: "again",
        })
      ).status,
    ).toBe(409);

    const cleared = await owner.delete(`/api/killswitches/${kill.body.data.id}`);
    expect(cleared.body.data.clearedAt).not.toBeNull();
    expect((await boot()).status).toBe(200);

    const org = await owner.post(`/api/orgs/${orgId}/killswitches`, {
      scope: "org",
      reason: "incident response",
    });
    const { token: ownerToken } = await loginDevice(app, owner);
    const ownerBoot = await cli(app, ownerToken).get(
      `/api/agent/bootstrap?projectId=${projectId}&env=development`,
    );
    expect(ownerBoot.body.error.code).toBe("KILLSWITCH_ACTIVE");
    expect((await dev.member.get(`/api/orgs/${orgId}/killswitches`)).status).toBe(403);
    await owner.delete(`/api/killswitches/${org.body.data.id}`);
    stop();
  });

  it("lists active dashboard sessions (current marked) and revoking one signs that member out", async () => {
    const { owner, orgId } = await signupOwner(app);
    const dev = await addMember(app, owner, orgId, "Sam");
    const sessions = await owner.get(`/api/orgs/${orgId}/sessions`);
    expect(sessions.status).toBe(200);
    expect(sessions.body.data.filter((s: { current: boolean }) => s.current)).toHaveLength(1);
    const devSession = sessions.body.data.find((s: { user: { id: string } }) => s.user.id === dev.userId);
    expect(devSession).toBeTruthy();
    expect((await dev.member.get("/api/auth/me")).status).toBe(200);
    expect((await owner.delete(`/api/sessions/${devSession.id}`)).body.data).toEqual({ revoked: true });
    expect((await dev.member.get("/api/auth/me")).status).toBe(401);
  });

  it("agent heartbeat marks the device's agent online with its version and tunnels", async () => {
    const { owner, orgId } = await signupOwner(app);
    const { token, deviceId } = await loginDevice(app, owner);
    const before = (await owner.get(`/api/orgs/${orgId}/devices`)).body.data.find(
      (d: { id: string }) => d.id === deviceId,
    );
    expect(before.agent.online).toBe(false);
    const beat = await cli(app, token)
      .post("/api/agent/heartbeat")
      .send({ version: "0.1.0", activeTunnels: 3 });
    expect(beat.status).toBe(200);
    const after = (await owner.get(`/api/orgs/${orgId}/devices`)).body.data.find(
      (d: { id: string }) => d.id === deviceId,
    );
    expect(after.agent).toMatchObject({ online: true, version: "0.1.0", activeTunnels: 3 });
    expect((await owner.post("/api/agent/heartbeat", { version: "x", activeTunnels: 0 })).status).toBe(403);
  });
});

describe("CLI tokens (FR-AUTH-002/003/004)", () => {
  it("FR-AUTH-003 refresh rotates; reusing a used refresh token signs the device out", async () => {
    const { owner } = await signupOwner(app);
    const { token, refreshToken, deviceId } = await loginDevice(app, owner);
    const first = await request(app).post("/api/cli/token/refresh").send({ refreshToken });
    expect(first.status).toBe(200);
    expect(first.body.data.refreshToken).not.toBe(refreshToken);
    expect((await cli(app, first.body.data.accessToken).get("/api/cli/whoami")).status).toBe(200);

    const events: BusEvent[] = [];
    const stop = bus.subscribe((e) => events.push(e));
    const reused = await request(app).post("/api/cli/token/refresh").send({ refreshToken });
    expect(reused.status).toBe(401);
    expect(reused.body.error.code).toBe("REFRESH_TOKEN_REUSED");
    expect(events.some((e) => e.type === "access.revoked" && e.deviceId === deviceId)).toBe(true);
    // Every token of that device is now dead, including the newest pair.
    expect((await cli(app, first.body.data.accessToken).get("/api/cli/whoami")).status).toBe(401);
    expect(
      (await request(app).post("/api/cli/token/refresh").send({ refreshToken: first.body.data.refreshToken }))
        .status,
    ).toBe(401);
    expect((await cli(app, token).get("/api/cli/whoami")).status).toBe(401);
    stop();
  });

  it("FR-AUTH-002 a legacy device token is exchanged once, then stops working", async () => {
    const { owner, userId } = await signupOwner(app);
    const { DeviceModel } = await import("../../src/models/device.model.js");
    const { hashToken } = await import("../../src/crypto/tokens.js");
    const legacy = "cbd_legacy_token_for_upgrade_test_0000000000";
    await DeviceModel.create({
      userId,
      name: "old-laptop",
      os: "darwin",
      tokenHash: hashToken(legacy),
      expiresAt: new Date(Date.now() + 86_400_000),
    });
    expect((await cli(app, legacy).get("/api/cli/whoami")).status).toBe(200);
    const exchanged = await request(app).post("/api/cli/token/refresh").send({ refreshToken: legacy });
    expect(exchanged.status).toBe(200);
    expect((await cli(app, exchanged.body.data.accessToken).get("/api/cli/whoami")).status).toBe(200);
    expect((await cli(app, legacy).get("/api/cli/whoami")).status).toBe(401);
    expect((await request(app).post("/api/cli/token/refresh").send({ refreshToken: legacy })).status).toBe(
      401,
    );
    void owner;
  });

  it("FR-AUTH-004 access tokens are ES256 JWTs verifiable with the published JWKS; expired or tampered ones fail", async () => {
    const { owner } = await signupOwner(app);
    const { token, deviceId } = await loginDevice(app, owner);
    const keys = await request(app).get("/.well-known/jwks.json");
    expect(keys.status).toBe(200);
    const [head, payload] = token.split(".");
    const header = JSON.parse(Buffer.from(head ?? "", "base64url").toString());
    const claims = JSON.parse(Buffer.from(payload ?? "", "base64url").toString());
    expect(header).toMatchObject({ alg: "ES256" });
    expect(claims).toMatchObject({ did: deviceId, sid: deviceId });
    expect(claims.exp - claims.iat).toBe(900);
    const jwk = keys.body.keys.find((k: { kid: string }) => k.kid === header.kid);
    const { verifyJwt } = await import("../../src/crypto/jwt.js");
    const { createPublicKey } = await import("node:crypto");
    expect(verifyJwt(token, "ES256", createPublicKey({ key: jwk, format: "jwk" }))).not.toBeNull();

    const { signAccessToken } = await import("../../src/services/token.service.js");
    const expired = await signAccessToken({ id: deviceId, userId: claims.sub }, -10);
    expect((await cli(app, expired.accessToken).get("/api/cli/whoami")).status).toBe(401);
    const tampered = `${head}.${Buffer.from(JSON.stringify({ ...claims, sub: "000000000000000000000000" })).toString("base64url")}.${token.split(".")[2]}`;
    expect((await cli(app, tampered).get("/api/cli/whoami")).status).toBe(401);
  });
});

describe("D11 private-only plain http upstreams (FR-GW-004)", () => {
  async function env() {
    const ctx = await signupOwner(app);
    const project = await ctx.owner.post(`/api/orgs/${ctx.orgId}/projects`, { name: "LLM" });
    return { ...ctx, envId: project.body.data.environments[0].id as string };
  }
  const http = (upstreamUrl: string) => ({ kind: "http", name: "llm", upstreamUrl, apiKey: "k" });

  it("accepts http:// for a private IP and refuses it for a public host, on create and on PATCH", async () => {
    const { owner, envId } = await env();
    const ok = await owner.post(`/api/environments/${envId}/resources`, http("http://10.0.4.12:8000"));
    expect(ok.status).toBe(201);
    const bad = await owner.post(`/api/environments/${envId}/resources`, {
      ...http("http://api.example.com"),
      name: "x",
    });
    expect(bad.status).toBe(400);
    expect(bad.body.error.details[0].path).toBe("upstreamUrl");
    const patch = await owner.patch(`/api/resources/${ok.body.data.id}`, {
      upstreamUrl: "http://api.example.com",
    });
    expect(patch.status).toBe(400);
    const tokenUrl = await owner.patch(`/api/resources/${ok.body.data.id}`, {
      tokenUrl: "http://10.0.0.1/token",
    });
    expect(tokenUrl.status).toBe(400);
  });
});

describe("D9 replace value is tested before it is stored (J2)", () => {
  it("PATCH with test:true refuses a failing credential with 422 and keeps the old one", async () => {
    const ctx = await signupOwner(app);
    const project = await ctx.owner.post(`/api/orgs/${ctx.orgId}/projects`, { name: "P" });
    const envId = project.body.data.environments[0].id as string;
    const r = await ctx.owner.post(`/api/environments/${envId}/resources`, {
      kind: "mongodb",
      name: "db",
      connectionUri: `${mongo.uri}shop`,
    });
    expect(r.status).toBe(201);
    const bad = await ctx.owner.patch(`/api/resources/${r.body.data.id}`, {
      connectionUri: "mongodb://u:WRONG_PW_88@127.0.0.1:1/shop",
      test: true,
    });
    expect(bad.status).toBe(422);
    expect(bad.body.error.code).toBe("SERVICE_TEST_FAILED");
    expect(JSON.stringify(bad.body)).not.toContain("WRONG_PW_88");
    const still = await ctx.owner.post(`/api/resources/${r.body.data.id}/test`, {});
    expect(still.body.data.ok).toBe(true);
  });
});

describe("D8 extra keys link to their service", () => {
  it("a plain variable can link to a resource, renders as plain, and is removed with it", async () => {
    const ctx = await signupOwner(app);
    const project = await ctx.owner.post(`/api/orgs/${ctx.orgId}/projects`, { name: "P" });
    const envId = project.body.data.environments[0].id as string;
    const stripe = await ctx.owner.post(`/api/environments/${envId}/resources`, {
      kind: "http",
      name: "stripe",
      upstreamUrl: "https://api.stripe.com",
      apiKey: "sk_live_x",
    });
    const pk = await ctx.owner.post(`/api/environments/${envId}/variables`, {
      type: "plain",
      key: "NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY",
      value: "pk_live_1",
      resourceId: stripe.body.data.id,
    });
    expect(pk.status).toBe(201);
    expect(pk.body.data).toMatchObject({
      type: "plain",
      value: "pk_live_1",
      resourceId: stripe.body.data.id,
    });
    const other = await ctx.owner.post(`/api/orgs/${ctx.orgId}/projects`, { name: "Q" });
    const foreignEnv = other.body.data.environments[0].id as string;
    const foreign = await ctx.owner.post(`/api/environments/${foreignEnv}/variables`, {
      type: "plain",
      key: "X",
      value: "1",
      resourceId: stripe.body.data.id,
    });
    expect(foreign.status).toBe(400);
    await ctx.owner.delete(`/api/resources/${stripe.body.data.id}`);
    const left = await ctx.owner.get(`/api/environments/${envId}/variables`);
    expect(left.body.data).toEqual([]);
  });
});

describe("J4 removing a service cleans up per-person logins", () => {
  it("deleting a resource removes its profile choice from grants", async () => {
    const ctx = await signupOwner(app);
    const { userId: bobId } = await addMember(app, ctx.owner, ctx.orgId, "Bob");
    const project = await ctx.owner.post(`/api/orgs/${ctx.orgId}/projects`, { name: "P" });
    const envId = project.body.data.environments[0].id as string;
    const db = await ctx.owner.post(`/api/environments/${envId}/resources`, {
      kind: "mongodb",
      name: "db",
      connectionUri: REAL_MONGO,
    });
    const profile = await ctx.owner.post(`/api/resources/${db.body.data.id}/profiles`, {
      name: "readonly",
      connectionUri: REAL_MONGO,
    });
    expect(profile.status).toBe(201);
    const grant = await ctx.owner.post(`/api/environments/${envId}/grants`, {
      userId: bobId,
      resourceProfiles: [{ resourceId: db.body.data.id, profile: "readonly" }],
    });
    expect(grant.status).toBe(201);
    await ctx.owner.delete(`/api/resources/${db.body.data.id}`);
    const stored = await GrantModel.findById(grant.body.data.id).lean();
    expect(stored?.resourceProfiles).toEqual([]);
  });
});
