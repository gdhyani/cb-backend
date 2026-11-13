import type { Express } from "express";
import mongoose from "mongoose";
import request from "supertest";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createApp } from "../../src/app.js";
import { connectMongo, disconnectMongo } from "../../src/clients/mongodb.client.js";
import { type BusEvent, bus } from "../../src/events/bus.js";
import { AuditEventModel } from "../../src/models/audit-event.model.js";
import { DeviceModel } from "../../src/models/device.model.js";
import { EnvironmentModel } from "../../src/models/environment.model.js";
import { GrantModel } from "../../src/models/grant.model.js";
import { InviteModel } from "../../src/models/invite.model.js";
import { KillSwitchModel } from "../../src/models/kill-switch.model.js";
import { MembershipModel } from "../../src/models/membership.model.js";
import { OrgCaModel } from "../../src/models/org-ca.model.js";
import { OrganizationModel } from "../../src/models/organization.model.js";
import { ProjectModel } from "../../src/models/project.model.js";
import { RefreshTokenModel } from "../../src/models/refresh-token.model.js";
import { ResourceModel } from "../../src/models/resource.model.js";
import { UserModel } from "../../src/models/user.model.js";
import { VariableModel } from "../../src/models/variable.model.js";
import { WebSessionModel } from "../../src/models/web-session.model.js";
import { addMember, type browser, loginDevice, signupOwner } from "../helpers/api.js";
import { useTestEnv } from "../helpers/env.js";
import { startMemoryMongo } from "../helpers/mongo.js";

let mongo: Awaited<ReturnType<typeof startMemoryMongo>>;
let app: Express;
const PASSWORD = "correct-horse-battery";
const REAL_MONGO = "mongodb://admin:ACCOUNT_DELETE_SECRET_PW@db.internal:27017/shop?authSource=admin";
const VISIBLE_SECRET = "VISIBLE_REAL_VALUE_DELETE_ME";

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

type Client = ReturnType<typeof browser>;

/** DELETE with a JSON body (the shared helper's delete sends none). */
function del(client: Client, url: string, body: object) {
  return client.raw.delete(url).set("x-cb-csrf", "1").send(body);
}

/** Org with a project, a brokered + visible variable, a mongodb service, a developer with a grant and a device. */
async function world() {
  const ctx = await signupOwner(app);
  const project = await ctx.owner.post(`/api/orgs/${ctx.orgId}/projects`, { name: "Shop API" });
  const envId = project.body.data.environments[0].id as string;
  const db = await ctx.owner.post(`/api/environments/${envId}/resources`, {
    kind: "mongodb",
    name: "main-db",
    connectionUri: REAL_MONGO,
  });
  expect(db.status).toBe(201);
  await ctx.owner.post(`/api/environments/${envId}/variables`, {
    type: "brokered",
    key: "MONGODB_URI",
    resourceId: db.body.data.id,
    field: "url",
  });
  await ctx.owner.post(`/api/environments/${envId}/variables`, {
    type: "visible",
    key: "LEGACY",
    value: VISIBLE_SECRET,
  });
  const bob = await addMember(app, ctx.owner, ctx.orgId, "Bob");
  const grant = await ctx.owner.post(`/api/environments/${envId}/grants`, { userId: bob.userId });
  expect(grant.status).toBe(201);
  await ctx.owner.post(`/api/orgs/${ctx.orgId}/invites`, { role: "developer" });
  return { ...ctx, projectId: project.body.data.id as string, envId, bob };
}

function captureBus(): { events: BusEvent[]; stop: () => void } {
  const events: BusEvent[] = [];
  const stop = bus.subscribe((e) => events.push(e));
  return { events, stop };
}

function expectNoSecret(body: unknown) {
  const text = JSON.stringify(body);
  expect(text).not.toContain("ACCOUNT_DELETE_SECRET_PW");
  expect(text).not.toContain(VISIBLE_SECRET);
  expect(text).not.toContain(PASSWORD);
}

describe("FR-ACC-001 delete account", () => {
  it("FR-ACC-001 refuses a wrong password (403 WRONG_PASSWORD) and a wrong confirmation (400)", async () => {
    const { owner } = await signupOwner(app);
    const wrong = await del(owner, "/api/auth/me", { password: "nope", confirm: "ada@example.com" });
    expect(wrong.status).toBe(403);
    expect(wrong.body).toMatchObject({ success: false, error: { code: "WRONG_PASSWORD" } });
    expect(wrong.body.error.correlationId).toEqual(expect.any(String));
    const mismatch = await del(owner, "/api/auth/me", { password: PASSWORD, confirm: "someone@else.com" });
    expect(mismatch.status).toBe(400);
    expect(mismatch.body.error.code).toBe("CONFIRMATION_MISMATCH");
    const empty = await del(owner, "/api/auth/me", { password: "", confirm: "ada@example.com" });
    expect(empty.body.error.code).toBe("VALIDATION_FAILED");
    expect(await UserModel.countDocuments()).toBe(1);
    expect((await owner.get("/api/auth/me")).status).toBe(200);
  });

  it("FR-ACC-001 removes the user, memberships, sessions, devices and grants; the old cookie gets 401", async () => {
    const { owner, orgId, envId, bob } = await world();
    // Bob is a developer; Ada stays the owner, so the org survives his deletion.
    const login = await request(app)
      .post("/api/auth/login")
      .send({ email: "bob@example.com", password: PASSWORD });
    const oldCookie = String(login.headers["set-cookie"]).split(";")[0] ?? "";
    expect((await request(app).get("/api/auth/me").set("cookie", oldCookie)).status).toBe(200);
    const device = await loginDevice(app, bob.member);
    expect(await GrantModel.countDocuments({ userId: bob.userId })).toBe(1);
    const bus = captureBus();

    const res = await del(bob.member, "/api/auth/me", { password: PASSWORD, confirm: "  BOB@example.com " });
    bus.stop();
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ success: true, data: { deleted: true } });
    expect(res.body.meta.correlationId).toEqual(expect.any(String));
    expect(String(res.headers["set-cookie"])).toMatch(/cb_session=;/);
    expectNoSecret(res.body);

    expect(await UserModel.exists({ _id: bob.userId })).toBeNull();
    expect(await MembershipModel.countDocuments({ userId: bob.userId })).toBe(0);
    expect(await WebSessionModel.countDocuments({ userId: bob.userId })).toBe(0);
    expect(await DeviceModel.countDocuments({ userId: bob.userId })).toBe(0);
    expect(await RefreshTokenModel.countDocuments({ deviceId: device.deviceId })).toBe(0);
    expect(await GrantModel.countDocuments({ userId: bob.userId })).toBe(0);
    expect((await request(app).get("/api/auth/me").set("cookie", oldCookie)).status).toBe(401);
    expect(
      (await request(app).get("/api/auth/me").set("authorization", `Bearer ${device.token}`)).status,
    ).toBe(401);
    expect(bus.events).toContainEqual(
      expect.objectContaining({ type: "access.revoked", scope: "device", deviceId: device.deviceId }),
    );
    expect(bus.events).toContainEqual(
      expect.objectContaining({ type: "access.revoked", scope: "membership", orgId, userId: bob.userId }),
    );

    // The org and its data stay; the owner sees the removal in the audit log.
    expect(await OrganizationModel.exists({ _id: orgId })).not.toBeNull();
    expect(await VariableModel.countDocuments({ environmentId: envId })).toBe(2);
    expect(await ResourceModel.countDocuments({ orgId })).toBe(1);
    expect(
      await AuditEventModel.exists({ orgId, action: "member.removed", target: bob.userId }),
    ).not.toBeNull();
    expect((await owner.get("/api/auth/me")).status).toBe(200);
  });

  it("FR-ACC-001 leaves an org with another owner intact, revokes their invites, drops stops aimed at them; audit actor reads Deleted user", async () => {
    const { owner, orgId, envId } = await world();
    const co = await addMember(app, owner, orgId, "Cora", "owner");
    // Cora does something audited before leaving.
    await co.member.post(`/api/environments/${envId}/variables`, {
      type: "plain",
      key: "PORT",
      value: "3000",
    });
    // Cora invites someone and is the target of a stop; neither outlives her account.
    const invite = await co.member.post(`/api/orgs/${orgId}/invites`, { role: "developer" });
    expect(invite.status).toBe(201);
    const stop = await owner.post(`/api/orgs/${orgId}/killswitches`, {
      scope: "user",
      targetId: co.userId,
      reason: "laptop lost",
    });
    expect(stop.status).toBe(201);
    const res = await del(co.member, "/api/auth/me", { password: PASSWORD, confirm: "cora@example.com" });
    expect(res.status).toBe(200);
    expect(await InviteModel.countDocuments({ createdBy: co.userId, revokedAt: null })).toBe(0);
    expect(await KillSwitchModel.countDocuments({ scope: "user", targetId: co.userId })).toBe(0);
    expect(await OrganizationModel.exists({ _id: orgId })).not.toBeNull();
    expect(await ProjectModel.countDocuments({ orgId })).toBe(1);
    expect(await MembershipModel.countDocuments({ orgId })).toBe(2);

    const audit = await owner.get(`/api/orgs/${orgId}/audit?pageSize=100`);
    expect(audit.status).toBe(200);
    expectNoSecret(audit.body);
    const removed = audit.body.data.find((e: { action: string }) => e.action === "member.removed");
    expect(removed.actor).toEqual({ id: co.userId, name: "Deleted user", email: "" });
    const earlier = audit.body.data.find(
      (e: { action: string; actor: { id: string } | null }) =>
        e.action.startsWith("variable.") && e.actor?.id === co.userId,
    );
    expect(earlier.actor).toEqual({ id: co.userId, name: "Deleted user", email: "" });
  });
});

describe("FR-ACC-002 delete organization", () => {
  it("FR-ACC-002 refuses non-owners, a wrong password and a wrong name", async () => {
    const { owner, orgId, bob } = await world();
    const admin = await addMember(app, owner, orgId, "Ann", "admin");
    for (const client of [bob.member, admin.member]) {
      const res = await del(client, `/api/orgs/${orgId}`, { password: PASSWORD, confirm: "Acme" });
      expect(res.status).toBe(403);
      expect(res.body.error.code).toBe("FORBIDDEN");
    }
    const wrongPw = await del(owner, `/api/orgs/${orgId}`, { password: "nope", confirm: "Acme" });
    expect(wrongPw.body.error.code).toBe("WRONG_PASSWORD");
    const wrongName = await del(owner, `/api/orgs/${orgId}`, { password: PASSWORD, confirm: "acme" });
    expect(wrongName.status).toBe(400);
    expect(wrongName.body.error.code).toBe("CONFIRMATION_MISMATCH");
    expect(await OrganizationModel.exists({ _id: orgId })).not.toBeNull();
  });

  it("FR-ACC-002 deletes the org and everything in it; members' accounts stay", async () => {
    const { owner, orgId, envId, bob } = await world();
    const other = await signupOwner(app, "-b");
    const bus = captureBus();
    const res = await del(owner, `/api/orgs/${orgId}`, { password: PASSWORD, confirm: " Acme " });
    bus.stop();
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ success: true, data: { deleted: true } });
    expectNoSecret(res.body);
    expect(bus.events).toContainEqual(
      expect.objectContaining({ type: "access.revoked", scope: "org", orgId }),
    );

    expect(await OrganizationModel.exists({ _id: orgId })).toBeNull();
    for (const model of [
      ProjectModel,
      EnvironmentModel,
      VariableModel,
      ResourceModel,
      GrantModel,
      InviteModel,
      MembershipModel,
      AuditEventModel,
      OrgCaModel,
    ] as const) {
      expect(await (model as typeof ProjectModel).countDocuments({ orgId })).toBe(0);
    }
    expect(await EnvironmentModel.exists({ _id: envId })).toBeNull();
    // Secrets left with the resources: nothing in the database still holds them.
    const dump = JSON.stringify(
      await Promise.all([
        ResourceModel.find().select("+secret +credentialsFile").lean(),
        VariableModel.find().lean(),
      ]),
    );
    expect(dump).not.toContain("main-db");
    expect(dump).not.toContain("LEGACY");

    expect(await UserModel.exists({ _id: bob.userId })).not.toBeNull();
    expect((await bob.member.get("/api/auth/me")).body.data.memberships).toEqual([]);
    expect((await owner.get("/api/auth/me")).body.data.memberships).toEqual([]);
    expect(await OrganizationModel.exists({ _id: other.orgId })).not.toBeNull();
    expect((await owner.get(`/api/orgs/${orgId}`)).status).toBe(404);
  });
});

describe("FR-ACC-003 deletion preview and sole-owner orgs", () => {
  it("FR-ACC-003 lists sole-owner orgs as deleted and others as left", async () => {
    const { owner, orgId } = await world();
    const b = await signupOwner(app, "-b");
    // Ada joins org B as an admin through an invite while signed in.
    const invite = await b.owner.post(`/api/orgs/${b.orgId}/invites`, { role: "admin" });
    const accept = await owner.post("/api/auth/accept-invite", { token: invite.body.data.token });
    expect(accept.status).toBe(200);

    const preview = await owner.get("/api/auth/me/deletion");
    expect(preview.status).toBe(200);
    expect(preview.body.data).toEqual({
      email: "ada@example.com",
      orgsDeleted: [{ id: orgId, name: "Acme", memberCount: 2 }],
      orgsLeft: [{ id: b.orgId, name: "Acme-b", role: "admin" }],
    });
  });

  it("FR-ACC-003 deleting a sole owner's account deletes their org including others' memberships", async () => {
    const { owner, orgId, bob } = await world();
    const res = await del(owner, "/api/auth/me", { password: PASSWORD, confirm: "ada@example.com" });
    expect(res.status).toBe(200);
    expect(await OrganizationModel.exists({ _id: orgId })).toBeNull();
    expect(await MembershipModel.countDocuments({ orgId })).toBe(0);
    expect(await ProjectModel.countDocuments({ orgId })).toBe(0);
    expect(await UserModel.exists({ _id: bob.userId })).not.toBeNull();
    expect((await bob.member.get("/api/auth/me")).body.data.memberships).toEqual([]);
  });
});
