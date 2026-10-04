import type { Express } from "express";
import request from "supertest";

/** Cookie-carrying browser-like client that sends the CSRF header on mutations. */
export function browser(app: Express) {
  const agent = request.agent(app);
  return {
    get: (url: string) => agent.get(url),
    post: (url: string, body?: object) =>
      agent
        .post(url)
        .set("x-cb-csrf", "1")
        .send(body ?? {}),
    patch: (url: string, body?: object) =>
      agent
        .patch(url)
        .set("x-cb-csrf", "1")
        .send(body ?? {}),
    put: (url: string, body?: object) =>
      agent
        .put(url)
        .set("x-cb-csrf", "1")
        .send(body ?? {}),
    delete: (url: string) => agent.delete(url).set("x-cb-csrf", "1"),
    raw: agent,
  };
}

/** CLI-like client authenticated with a device token. */
export function cli(app: Express, token: string) {
  const auth = { authorization: `Bearer ${token}` };
  return {
    get: (url: string) => request(app).get(url).set(auth),
    post: (url: string, body?: object) =>
      request(app)
        .post(url)
        .set(auth)
        .send(body ?? {}),
  };
}

export async function signupOwner(app: Express, suffix = "") {
  const owner = browser(app);
  const res = await owner.post("/api/auth/signup", {
    name: `Ada${suffix}`,
    email: `ada${suffix}@example.com`,
    password: "correct-horse-battery",
    orgName: `Acme${suffix}`,
  });
  if (res.status !== 201) throw new Error(`signup failed: ${res.status} ${JSON.stringify(res.body)}`);
  return {
    owner,
    orgId: res.body.data.memberships[0].orgId as string,
    userId: res.body.data.user.id as string,
  };
}

/** Invites a new member through the real invite flow and returns their logged-in client. */
export async function addMember(
  app: Express,
  owner: ReturnType<typeof browser>,
  orgId: string,
  name: string,
  role = "developer",
) {
  const invite = await owner.post(`/api/orgs/${orgId}/invites`, { role });
  const member = browser(app);
  const accepted = await member.post("/api/auth/accept-invite", {
    token: invite.body.data.token,
    name,
    email: `${name.toLowerCase()}@example.com`,
    password: "correct-horse-battery",
  });
  if (accepted.status !== 200) throw new Error(`accept failed: ${JSON.stringify(accepted.body)}`);
  return { member, userId: accepted.body.data.me.user.id as string };
}

/** Full device-code login for a member; returns the device token. */
export async function loginDevice(app: Express, member: ReturnType<typeof browser>, deviceName = "laptop") {
  const start = await request(app).post("/api/cli/device/start").send({ deviceName, os: "darwin" });
  await member.post("/api/cli/device/approve", { userCode: start.body.data.userCode });
  const token = await request(app)
    .post("/api/cli/device/token")
    .send({ deviceCode: start.body.data.deviceCode });
  return {
    token: token.body.data.accessToken as string,
    refreshToken: token.body.data.refreshToken as string,
    deviceId: token.body.data.device.id as string,
  };
}
