import { createHmac } from "node:crypto";
import type http from "node:http";
import type { AddressInfo } from "node:net";
import type { Express } from "express";
import mongoose from "mongoose";
import Stripe from "stripe";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createApp } from "../../src/app.js";
import { connectMongo, disconnectMongo } from "../../src/clients/mongodb.client.js";
import { loadEnv, setEnv } from "../../src/config/env.js";
import { resetUpstreamDispatcher } from "../../src/gateway/http/upstream.js";
import { WebhookDeliveryModel } from "../../src/models/webhook-delivery.model.js";
import { WebhookEventModel } from "../../src/models/webhook-event.model.js";
import { WebhookOwnerModel } from "../../src/models/webhook-owner.model.js";
import { createServer } from "../../src/server.js";
import { sweepWebhooks } from "../../src/services/webhook-delivery.service.js";
import { localListener } from "../helpers/agent.js";
import { addMember, cli, loginDevice, signupOwner } from "../helpers/api.js";
import { testEnvVars } from "../helpers/env.js";
import { startMockPayments } from "../helpers/mock-payments.js";
import { startMemoryMongo } from "../helpers/mongo.js";
import { openEvents, waitFor } from "../helpers/sse.js";

const STRIPE_KEY = "sk_test_REAL_STRIPE_KEY_6631";
const SNAPSHOT_WHSEC = "whsec_REAL_SNAPSHOT_SECRET_1182";
const THIN_WHSEC = "whsec_REAL_THIN_SECRET_7743";

let backendDb: Awaited<ReturnType<typeof startMemoryMongo>>;
let payments: Awaited<ReturnType<typeof startMockPayments>>;
let server: http.Server;
let app: Express;
let base: string;

beforeAll(async () => {
  [backendDb, payments] = await Promise.all([
    startMemoryMongo(),
    startMockPayments({ stripeKey: STRIPE_KEY, razorpayKeyId: "rzp_test_Keyid12345", razorpaySecret: "x" }),
  ]);
  setEnv(
    loadEnv({
      ...testEnvVars(backendDb.uri),
      UPSTREAM_EXTRA_CA_FILE: payments.caFile,
      PUBLIC_URL: "https://hooks.cb.test",
    }),
  );
  resetUpstreamDispatcher();
  await connectMongo(backendDb.uri);
  app = createApp();
  server = createServer(app).server;
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}, 120_000);
afterAll(async () => {
  server.closeAllConnections();
  server.close();
  await disconnectMongo();
  await backendDb.stop();
  payments.close();
});
beforeEach(async () => {
  await mongoose.connection.db?.dropDatabase();
  await Promise.all([
    WebhookEventModel.syncIndexes(),
    WebhookDeliveryModel.syncIndexes(),
    WebhookOwnerModel.syncIndexes(),
  ]);
});

async function project(opts: { stripeKey?: boolean } = {}) {
  const { owner, orgId } = await signupOwner(app);
  const p = await owner.post(`/api/orgs/${orgId}/projects`, { name: "Shop" });
  const projectId = p.body.data.id as string;
  const envId = p.body.data.environments[0].id as string;
  const services = `/api/environments/${envId}/services`;
  let stripeApiId = "";
  if (opts.stripeKey !== false) {
    const s = await owner.post(services, {
      key: "STRIPE_SECRET_KEY",
      preset: "stripe",
      test: false,
      resource: { kind: "http", apiKey: STRIPE_KEY, upstreamUrl: payments.url, redirectHosts: [] },
    });
    expect(s.status, JSON.stringify(s.body)).toBe(201);
    stripeApiId = s.body.data.service.id;
  }
  const device = async (name: string) => {
    const m = await addMember(app, owner, orgId, name);
    await owner.post(`/api/environments/${envId}/grants`, { userId: m.userId });
    const login = await loginDevice(app, m.member, `${name}-laptop`);
    const boot = await cli(app, login.token).get(
      `/api/agent/bootstrap?projectId=${projectId}&env=development`,
    );
    return { ...login, member: m.member, plain: boot.body.data.plain as Record<string, string> };
  };
  return { owner, orgId, envId, projectId, services, stripeApiId, device };
}

const stripeSign = (body: string, secret: string, t = Math.floor(Date.now() / 1000)) =>
  `t=${t},v1=${createHmac("sha256", secret).update(`${t}.${body}`).digest("hex")}`;
const postStripe = (serviceId: string, event: object, secret: string) => {
  const body = JSON.stringify(event);
  return fetch(`${base}/api/hooks/${serviceId}`, {
    method: "POST",
    headers: { "content-type": "application/json", "stripe-signature": stripeSign(body, secret) },
    body,
  });
};
const decode = (w: Record<string, unknown>) => Buffer.from(String(w.body), "base64");

describe("FR-WH-001 Connect Stripe: cb creates the endpoint with the stored key; nobody copies a URL or secret", () => {
  it("a Stripe webhook variable can be created before it has a secret; webhooks are refused until it does", async () => {
    const { owner, services } = await project();
    const r = await owner.post(services, {
      key: "STRIPE_WEBHOOK_SECRET",
      resource: { kind: "webhook", provider: "stripe", path: "/api/webhooks/stripe" },
    });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    const svc = r.body.data.service;
    expect(svc.config.secretsSet).toEqual({ snapshot: false, thin: false });
    const hook = await postStripe(
      svc.id,
      { id: "evt_1", object: "event", type: "x", data: { object: {} } },
      "whsec_any",
    );
    expect(hook.status).toBe(400);
  });

  it("connect creates one all-events endpoint at the cb URL, stores its secret, and accepts what Stripe signs", async () => {
    const { owner, services } = await project();
    const r = await owner.post(services, {
      key: "STRIPE_WEBHOOK_SECRET",
      resource: { kind: "webhook", provider: "stripe", path: "/api/webhooks/stripe" },
    });
    const id = r.body.data.service.id as string;
    const c = await owner.post(`/api/resources/${id}/webhook/connect`, {});
    expect(c.status, JSON.stringify(c.body)).toBe(200);
    const svc = c.body.data;
    expect(svc.config.secretsSet).toEqual({ snapshot: true, thin: false });
    expect(svc.config.connectedUrl).toBe(`https://hooks.cb.test/api/hooks/${id}`);
    expect(svc.config.stripeEndpointId).toMatch(/^we_/);
    const endpoint = payments.endpoints.get(svc.config.stripeEndpointId);
    expect(endpoint?.url).toBe(`https://hooks.cb.test/api/hooks/${id}`);
    expect(endpoint?.events).toEqual(["*"]);
    // The secret Stripe returned is stored, never shown.
    expect(JSON.stringify(c.body)).not.toContain(endpoint?.secret);
    const hook = await postStripe(
      id,
      {
        id: "evt_conn1",
        object: "event",
        type: "payment_intent.created",
        data: { object: { id: "pi_Abcdefgh1" } },
      },
      endpoint?.secret ?? "",
    );
    expect(hook.status).toBe(200);

    // Connecting again (e.g. the cb address changed) updates the same endpoint; the secret stays valid.
    const again = await owner.post(`/api/resources/${id}/webhook/connect`, {});
    expect(again.status).toBe(200);
    expect(again.body.data.config.stripeEndpointId).toBe(svc.config.stripeEndpointId);
    expect(payments.endpoints.size).toBe(1);
    const hook2 = await postStripe(
      id,
      {
        id: "evt_conn2",
        object: "event",
        type: "payment_intent.created",
        data: { object: { id: "pi_Abcdefgh2" } },
      },
      endpoint?.secret ?? "",
    );
    expect(hook2.status).toBe(200);
  });

  it("an endpoint deleted in Stripe is created again on the next connect", async () => {
    const { owner, services } = await project();
    const r = await owner.post(services, {
      key: "STRIPE_WEBHOOK_SECRET",
      resource: { kind: "webhook", provider: "stripe", path: "/api/webhooks/stripe" },
    });
    const id = r.body.data.service.id as string;
    const first = await owner.post(`/api/resources/${id}/webhook/connect`, {});
    payments.endpoints.delete(first.body.data.config.stripeEndpointId);
    const second = await owner.post(`/api/resources/${id}/webhook/connect`, {});
    expect(second.status, JSON.stringify(second.body)).toBe(200);
    expect(second.body.data.config.stripeEndpointId).not.toBe(first.body.data.config.stripeEndpointId);
  });

  it("without a Stripe secret key in the environment, connect explains what to add", async () => {
    const { owner, services } = await project({ stripeKey: false });
    const r = await owner.post(services, {
      key: "STRIPE_WEBHOOK_SECRET",
      resource: { kind: "webhook", provider: "stripe", path: "/api/webhooks/stripe" },
    });
    const c = await owner.post(`/api/resources/${r.body.data.service.id}/webhook/connect`, {});
    expect(c.status).toBe(400);
    expect(c.body.error.message).toMatch(/Stripe secret key/);
  });

  it("developers cannot connect (admin only)", async () => {
    const { owner, services, device } = await project();
    const r = await owner.post(services, {
      key: "STRIPE_WEBHOOK_SECRET",
      resource: { kind: "webhook", provider: "stripe", path: "/api/webhooks/stripe" },
    });
    const bob = await device("Bob");
    const c = await bob.member.post(`/api/resources/${r.body.data.service.id}/webhook/connect`, {});
    expect(c.status).toBe(403);
  });
});

describe("FR-WH-001 one Stripe variable, one cb URL for snapshot and thin destinations", () => {
  it("each destination's events verify with its own secret and reach the app at the right path", async () => {
    const { owner, services, envId, device, projectId } = await project();
    const r = await owner.post(services, {
      key: "STRIPE_WEBHOOK_SECRET",
      resource: {
        kind: "webhook",
        provider: "stripe",
        path: "/api/webhooks/stripe",
        signingSecret: SNAPSHOT_WHSEC,
        thinSigningSecret: THIN_WHSEC,
        thinPath: "/api/webhooks/stripe-thin",
      },
    });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    const id = r.body.data.service.id as string;
    expect(r.body.data.service.config.secretsSet).toEqual({ snapshot: true, thin: true });
    expect(JSON.stringify(r.body)).not.toContain(THIN_WHSEC);
    const bob = await device("Bob");
    await cli(app, bob.token).post("/api/agent/webhooks/listen", {
      projectId,
      env: "development",
      unmatched: true,
    });
    const events = openEvents(base, bob.token, envId);
    await waitFor(() => events.of("ready").length);

    const snap = await postStripe(
      id,
      {
        id: "evt_snap1",
        object: "event",
        type: "customer.created",
        data: { object: { id: "cus_Abcdefgh1" } },
      },
      SNAPSHOT_WHSEC,
    );
    expect(snap.status).toBe(200);
    const thinEvent = {
      id: "evt_thin1",
      object: "v2.core.event",
      type: "v1.customer.created",
      related_object: { id: "cus_Abcdefgh2", type: "customer", url: "/v1/customers/cus_Abcdefgh2" },
    };
    expect((await postStripe(id, thinEvent, THIN_WHSEC)).status).toBe(200);
    // A secret pasted into the other field still verifies; a wrong one never does.
    expect((await postStripe(id, { ...thinEvent, id: "evt_thin2" }, SNAPSHOT_WHSEC)).status).toBe(200);
    expect((await postStripe(id, { ...thinEvent, id: "evt_thin3" }, "whsec_attacker")).status).toBe(400);

    for (let i = 0; i < 4; i++) await sweepWebhooks(new Date(Date.now() + 20_000));
    const pushes = await waitFor(() => (events.of("webhook").length >= 3 ? events.of("webhook") : undefined));
    const byId = new Map(pushes.map((p) => [JSON.parse(decode(p).toString()).id as string, p]));
    expect(byId.get("evt_snap1")?.path).toBe("/api/webhooks/stripe");
    expect(byId.get("evt_thin1")?.path).toBe("/api/webhooks/stripe-thin");
    // Both re-signed with Bob's one fake: the app verifies them with STRIPE_WEBHOOK_SECRET as before.
    const snapPush = byId.get("evt_snap1") as Record<string, unknown>;
    const thinPush = byId.get("evt_thin1") as Record<string, unknown>;
    const fake = bob.plain.STRIPE_WEBHOOK_SECRET ?? "";
    expect(
      Stripe.webhooks.constructEvent(
        decode(snapPush),
        (snapPush.headers as Record<string, string>)["stripe-signature"] ?? "",
        fake,
      ).id,
    ).toBe("evt_snap1");
    const stripe = new Stripe("sk_test_unused");
    const note = stripe.parseEventNotification(
      decode(thinPush).toString(),
      (thinPush.headers as Record<string, string>)["stripe-signature"] ?? "",
      fake,
    );
    expect(note.id).toBe("evt_thin1");
    await events.close();
  });

  it("thin events can use their own key name: a second fake signs them", async () => {
    const { owner, services, envId, device, projectId } = await project();
    const r = await owner.post(services, {
      key: "STRIPE_WEBHOOK_SECRET",
      extras: [{ key: "STRIPE_THIN_WEBHOOK_SECRET", field: "thinSecret" }],
      resource: {
        kind: "webhook",
        provider: "stripe",
        path: "/api/webhooks/stripe",
        signingSecret: SNAPSHOT_WHSEC,
        thinSigningSecret: THIN_WHSEC,
      },
    });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    const id = r.body.data.service.id as string;
    const bob = await device("Bob");
    expect(bob.plain.STRIPE_THIN_WEBHOOK_SECRET).toMatch(/^whsec_/);
    expect(bob.plain.STRIPE_THIN_WEBHOOK_SECRET).not.toBe(bob.plain.STRIPE_WEBHOOK_SECRET);
    await cli(app, bob.token).post("/api/agent/webhooks/listen", {
      projectId,
      env: "development",
      unmatched: true,
    });
    const events = openEvents(base, bob.token, envId);
    await waitFor(() => events.of("ready").length);
    await postStripe(
      id,
      {
        id: "evt_thinK",
        object: "v2.core.event",
        type: "v1.customer.created",
        related_object: { id: "cus_Abcdefgh9", type: "customer" },
      },
      THIN_WHSEC,
    );
    for (let i = 0; i < 4; i++) await sweepWebhooks(new Date(Date.now() + 20_000));
    const push = await waitFor(() => events.of("webhook")[0]);
    expect(push.path).toBe("/api/webhooks/stripe");
    const sig = (push.headers as Record<string, string>)["stripe-signature"] ?? "";
    const stripe = new Stripe("sk_test_unused");
    expect(
      stripe.parseEventNotification(decode(push).toString(), sig, bob.plain.STRIPE_THIN_WEBHOOK_SECRET ?? "")
        .id,
    ).toBe("evt_thinK");
    expect(() =>
      stripe.parseEventNotification(decode(push).toString(), sig, bob.plain.STRIPE_WEBHOOK_SECRET ?? ""),
    ).toThrow();
    await events.close();
  });

  it("adding the thin secret later keeps the snapshot secret", async () => {
    const { owner, services } = await project();
    const r = await owner.post(services, {
      key: "STRIPE_WEBHOOK_SECRET",
      resource: { kind: "webhook", provider: "stripe", path: "/w", signingSecret: SNAPSHOT_WHSEC },
    });
    const id = r.body.data.service.id as string;
    const u = await owner.patch(`/api/resources/${id}`, { thinSigningSecret: THIN_WHSEC });
    expect(u.status, JSON.stringify(u.body)).toBe(200);
    expect(u.body.data.config.secretsSet).toEqual({ snapshot: true, thin: true });
    const ev = { id: "evt_s9", object: "event", type: "x", data: { object: { id: "cus_Abcdefgh7" } } };
    expect((await postStripe(id, ev, SNAPSHOT_WHSEC)).status).toBe(200);
    expect((await postStripe(id, { ...ev, id: "evt_t9", object: "v2.core.event" }, THIN_WHSEC)).status).toBe(
      200,
    );
  });

  it("thin settings are Stripe-only and thin secrets must be whsec_", async () => {
    const { owner, services } = await project();
    const rzp = await owner.post(services, {
      key: "RAZORPAY_WEBHOOK_SECRET",
      resource: { kind: "webhook", provider: "razorpay", path: "/w", thinSigningSecret: "whsec_abcdefgh" },
    });
    expect(rzp.status).toBe(400);
    const bad = await owner.post(services, {
      key: "STRIPE_WEBHOOK_SECRET",
      resource: { kind: "webhook", provider: "stripe", path: "/w", thinSigningSecret: "nope12345" },
    });
    expect(bad.status).toBe(400);
  });
});

describe("FR-WH-001 Razorpay: cb generates the signing secret; the admin pastes URL and secret once", () => {
  it("returns the generated secret only in the create answer, and webhooks signed with it are accepted", async () => {
    const { owner, services, envId } = await project({ stripeKey: false });
    const r = await owner.post(services, {
      key: "RAZORPAY_WEBHOOK_SECRET",
      resource: { kind: "webhook", provider: "razorpay", path: "/api/webhooks/razorpay" },
    });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    const secret = r.body.data.service.generatedSecret as string;
    expect(secret).toMatch(/^[A-Za-z0-9_-]{32,}$/);
    const list = await owner.get(`/api/environments/${envId}/resources`);
    expect(JSON.stringify(list.body)).not.toContain(secret);
    const body = JSON.stringify({
      event: "payment.captured",
      payload: { payment: { entity: { id: "pay_Abcdefgh1" } } },
    });
    const sign = (s: string) => createHmac("sha256", s).update(body).digest("hex");
    const id = r.body.data.service.id as string;
    const post = (s: string, eventId: string) =>
      fetch(`${base}/api/hooks/${id}`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-razorpay-signature": sign(s),
          "x-razorpay-event-id": eventId,
        },
        body,
      });
    expect((await post(secret, "e1")).status).toBe(200);

    // A new secret on request (lost or leaked); the old one stops working at once.
    const regen = await owner.patch(`/api/resources/${id}`, { regenerateSecret: true });
    expect(regen.status, JSON.stringify(regen.body)).toBe(200);
    const fresh = regen.body.data.generatedSecret as string;
    expect(fresh).toMatch(/^[A-Za-z0-9_-]{32,}$/);
    expect(fresh).not.toBe(secret);
    expect((await post(secret, "e2")).status).toBe(400);
  });
});

describe("FR-WH-003 Send to me: events nobody owns (dashboard tests, stripe trigger) reach the admin's own machine", () => {
  it("queues the unmatched event for the caller's devices only", async () => {
    const { owner, services, envId, device, projectId } = await project();
    const r = await owner.post(services, {
      key: "STRIPE_WEBHOOK_SECRET",
      resource: { kind: "webhook", provider: "stripe", path: "/w", signingSecret: SNAPSHOT_WHSEC },
    });
    const id = r.body.data.service.id as string;
    const bob = await device("Bob");
    // The owner signs in with cb on their own laptop too.
    const ownerLogin = await loginDevice(app, owner, "owner-laptop");
    await cli(app, ownerLogin.token).get(`/api/agent/bootstrap?projectId=${projectId}&env=development`);
    const ownerEvents = openEvents(base, ownerLogin.token, envId);
    const bobEvents = openEvents(base, bob.token, envId);
    await waitFor(() => ownerEvents.of("ready").length && bobEvents.of("ready").length);

    await postStripe(
      id,
      {
        id: "evt_test1",
        object: "event",
        type: "charge.succeeded",
        data: { object: { id: "ch_Nobody0001" } },
      },
      SNAPSHOT_WHSEC,
    );
    for (let i = 0; i < 4; i++) await sweepWebhooks(new Date(Date.now() + 20_000));
    const ev = await WebhookEventModel.findOne({ eventId: "evt_test1" }).lean();
    expect(ev?.routing).toBe("unmatched");

    const s = await owner.post(`/api/webhook-events/${ev?._id}/send-to-me`, {});
    expect(s.status, JSON.stringify(s.body)).toBe(200);
    expect(s.body.data.queued).toBe(1);
    const push = await waitFor(() => ownerEvents.of("webhook")[0]);
    expect(JSON.parse(decode(push).toString()).id).toBe("evt_test1");
    await new Promise((res) => setTimeout(res, 200));
    expect(bobEvents.of("webhook")).toHaveLength(0);

    // Again: the same delivery is sent once more (new generation), not a second row.
    const again = await owner.post(`/api/webhook-events/${ev?._id}/send-to-me`, {});
    expect(again.body.data.queued).toBe(1);
    expect(await WebhookDeliveryModel.countDocuments({ eventRef: ev?._id })).toBe(1);
    await Promise.all([ownerEvents.close(), bobEvents.close()]);
  });

  it("explains that cb must be signed in on the caller's machine when it has no device", async () => {
    const { owner, services } = await project();
    const r = await owner.post(services, {
      key: "STRIPE_WEBHOOK_SECRET",
      resource: { kind: "webhook", provider: "stripe", path: "/w", signingSecret: SNAPSHOT_WHSEC },
    });
    await postStripe(
      r.body.data.service.id,
      { id: "evt_x1", object: "event", type: "x", data: { object: {} } },
      SNAPSHOT_WHSEC,
    );
    const ev = await WebhookEventModel.findOne({ eventId: "evt_x1" }).lean();
    const s = await owner.post(`/api/webhook-events/${ev?._id}/send-to-me`, {});
    expect(s.status).toBe(400);
    expect(s.body.error.message).toMatch(/cb login/);
  });
});

void localListener;

describe("review fixes", () => {
  it("thin settings cannot be added to a Razorpay webhook later either", async () => {
    const { owner, services } = await project({ stripeKey: false });
    const r = await owner.post(services, {
      key: "RAZORPAY_WEBHOOK_SECRET",
      resource: { kind: "webhook", provider: "razorpay", path: "/w" },
    });
    const id = r.body.data.service.id as string;
    expect((await owner.patch(`/api/resources/${id}`, { thinSigningSecret: "whsec_abcdefgh" })).status).toBe(
      400,
    );
    expect((await owner.patch(`/api/resources/${id}`, { thinPath: "/t" })).status).toBe(400);
  });

  it("Connect fails clearly when Stripe answers a create without a signing secret", async () => {
    const { owner, services, envId } = await project();
    const r = await owner.post(services, {
      key: "STRIPE_WEBHOOK_SECRET",
      resource: { kind: "webhook", provider: "stripe", path: "/w" },
    });
    payments.omitSecretOnce();
    const c = await owner.post(`/api/resources/${r.body.data.service.id}/webhook/connect`, {});
    expect(c.status).toBe(422);
    const list = await owner.get(`/api/environments/${envId}/resources`);
    const after = list.body.data.find((x: { id: string }) => x.id === r.body.data.service.id);
    expect(after.config.stripeEndpointId).toBeUndefined();
  });

  it("Send to me again after the delivery expired sends it again (not a silent 0)", async () => {
    const { owner, services, envId, projectId } = await project();
    const r = await owner.post(services, {
      key: "STRIPE_WEBHOOK_SECRET",
      resource: { kind: "webhook", provider: "stripe", path: "/w", signingSecret: SNAPSHOT_WHSEC },
    });
    const ownerLogin = await loginDevice(app, owner, "owner-laptop");
    await cli(app, ownerLogin.token).get(`/api/agent/bootstrap?projectId=${projectId}&env=development`);
    await postStripe(
      r.body.data.service.id,
      { id: "evt_exp1", object: "event", type: "x", data: { object: {} } },
      SNAPSHOT_WHSEC,
    );
    const ev = await WebhookEventModel.findOne({ eventId: "evt_exp1" }).lean();
    expect((await owner.post(`/api/webhook-events/${ev?._id}/send-to-me`, {})).body.data.queued).toBe(1);
    await WebhookDeliveryModel.updateMany({ eventRef: ev?._id }, { status: "expired" });
    const again = await owner.post(`/api/webhook-events/${ev?._id}/send-to-me`, {});
    expect(again.body.data.queued).toBe(1);
    expect((await WebhookDeliveryModel.findOne({ eventRef: ev?._id }).lean())?.status).toBe("pending");
    void envId;
  });
});
