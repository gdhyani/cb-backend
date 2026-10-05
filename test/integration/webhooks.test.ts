import { createHmac } from "node:crypto";
import type http from "node:http";
import type { AddressInfo } from "node:net";
import type { Express } from "express";
import mongoose from "mongoose";
import Razorpay from "razorpay";
import Stripe from "stripe";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createApp } from "../../src/app.js";
import { connectMongo, disconnectMongo } from "../../src/clients/mongodb.client.js";
import { loadEnv, setEnv } from "../../src/config/env.js";
import { resetUpstreamDispatcher } from "../../src/gateway/http/upstream.js";
import { GrantModel } from "../../src/models/grant.model.js";
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

const STRIPE_KEY = "sk_test_REAL_STRIPE_KEY_5521";
const STRIPE_WHSEC = "whsec_REAL_STRIPE_SIGNING_9931";
const RZP_KEY_ID = "rzp_test_Keyid12345";
const RZP_SECRET = "REAL_RZP_SECRET_7781";
const RZP_WHSEC = "REAL_RZP_WEBHOOK_SECRET_3317";

let backendDb: Awaited<ReturnType<typeof startMemoryMongo>>;
let payments: Awaited<ReturnType<typeof startMockPayments>>;
let server: http.Server;
let app: Express;
let base: string;

beforeAll(async () => {
  [backendDb, payments] = await Promise.all([
    startMemoryMongo(),
    startMockPayments({ stripeKey: STRIPE_KEY, razorpayKeyId: RZP_KEY_ID, razorpaySecret: RZP_SECRET }),
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

/** Shop project: Stripe + Razorpay keys, both webhook secrets, and two developers (Bob, Cara) on their own laptops. */
async function shop() {
  const { owner, orgId } = await signupOwner(app);
  const project = await owner.post(`/api/orgs/${orgId}/projects`, { name: "Shop" });
  const projectId = project.body.data.id as string;
  const envId = project.body.data.environments[0].id as string;
  const services = `/api/environments/${envId}/services`;
  const stripe = await owner.post(services, {
    key: "STRIPE_SECRET_KEY",
    preset: "stripe",
    test: false,
    resource: { kind: "http", apiKey: STRIPE_KEY, upstreamUrl: payments.url, redirectHosts: [] },
  });
  expect(stripe.status, JSON.stringify(stripe.body)).toBe(201);
  const rzp = await owner.post(services, {
    key: "RAZORPAY_KEY_SECRET",
    preset: "razorpay",
    test: false,
    resource: {
      kind: "http",
      apiKey: RZP_SECRET,
      basicUser: RZP_KEY_ID,
      upstreamUrl: payments.url,
      redirectHosts: [],
    },
  });
  expect(rzp.status, JSON.stringify(rzp.body)).toBe(201);
  const whStripe = await owner.post(services, {
    key: "STRIPE_WEBHOOK_SECRET",
    resource: { kind: "webhook", provider: "stripe", path: "/webhooks/stripe", signingSecret: STRIPE_WHSEC },
  });
  expect(whStripe.status, JSON.stringify(whStripe.body)).toBe(201);
  const whRzp = await owner.post(services, {
    key: "RAZORPAY_WEBHOOK_SECRET",
    resource: {
      kind: "webhook",
      provider: "razorpay",
      path: "/webhooks/razorpay",
      port: 4000,
      signingSecret: RZP_WHSEC,
    },
  });
  expect(whRzp.status, JSON.stringify(whRzp.body)).toBe(201);

  const dev = async (name: string) => {
    const m = await addMember(app, owner, orgId, name);
    await owner.post(`/api/environments/${envId}/grants`, { userId: m.userId });
    const login = await loginDevice(app, m.member, `${name}-laptop`);
    const boot = await cli(app, login.token).get(
      `/api/agent/bootstrap?projectId=${projectId}&env=development`,
    );
    const plain = boot.body.data.plain as Record<string, string>;
    const stripeApi = await localListener(base, login.token, {
      layer: "1",
      env: envId,
      resource: stripe.body.data.service.id,
    });
    const rzpApi = await localListener(base, login.token, {
      layer: "1",
      env: envId,
      resource: rzp.body.data.service.id,
    });
    return {
      ...login,
      plain,
      /** The app creating a PaymentIntent with its fake key, through the gateway. */
      createPaymentIntent: async () => {
        const r = await fetch(`http://127.0.0.1:${stripeApi.port}/v1/payment_intents`, {
          method: "POST",
          headers: {
            authorization: `Bearer ${plain.STRIPE_SECRET_KEY}`,
            "content-type": "application/x-www-form-urlencoded",
          },
          body: "amount=500&currency=usd",
        });
        expect(r.status).toBe(200);
        return (await r.json()) as { id: string };
      },
      createOrder: async () => {
        const basic = Buffer.from(`${RZP_KEY_ID}:${plain.RAZORPAY_KEY_SECRET}`).toString("base64");
        const r = await fetch(`http://127.0.0.1:${rzpApi.port}/v1/orders`, {
          method: "POST",
          headers: { authorization: `Basic ${basic}`, "content-type": "application/json" },
          body: JSON.stringify({ amount: 500, currency: "INR" }),
        });
        expect(r.status).toBe(200);
        return (await r.json()) as { id: string };
      },
      close: () => {
        stripeApi.close();
        rzpApi.close();
      },
    };
  };
  const bob = await dev("Bob");
  const cara = await dev("Cara");
  return {
    owner,
    envId,
    bob,
    cara,
    hooks: {
      stripe: whStripe.body.data.service.id as string,
      razorpay: whRzp.body.data.service.id as string,
    },
  };
}

const stripeSign = (body: string, secret = STRIPE_WHSEC, t = Math.floor(Date.now() / 1000)) =>
  `t=${t},v1=${createHmac("sha256", secret).update(`${t}.${body}`).digest("hex")}`;

async function postStripe(serviceId: string, event: object, secret = STRIPE_WHSEC) {
  const body = JSON.stringify(event);
  return fetch(`${base}/api/hooks/${serviceId}`, {
    method: "POST",
    headers: { "content-type": "application/json", "stripe-signature": stripeSign(body, secret) },
    body,
  });
}

async function postRazorpay(serviceId: string, event: object, eventId: string) {
  const body = JSON.stringify(event);
  return fetch(`${base}/api/hooks/${serviceId}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-razorpay-signature": createHmac("sha256", RZP_WHSEC).update(body).digest("hex"),
      "x-razorpay-event-id": eventId,
    },
    body,
  });
}

const piEvent = (id: string, piId: string, type = "payment_intent.succeeded") => ({
  id,
  object: "event",
  type,
  data: { object: { id: piId, object: "payment_intent" } },
});

const decode = (w: Record<string, unknown>) => Buffer.from(String(w.body), "base64");
const ack = (token: string, deliveryId: unknown, body: object = { ok: true, status: 200 }) =>
  cli(app, token).post(`/api/agent/webhooks/${String(deliveryId)}/ack`, body);

describe("webhooks method 1: central ingress → only the device that caused it (FR-WH-001..004)", () => {
  it("bootstrap hands each device its own fake signing secret; real secrets never leave the backend (S1)", async () => {
    const { owner, envId, bob, cara, hooks } = await shop();
    // The admin pastes this into the provider's webhook settings.
    const services = await owner.get(`/api/environments/${envId}/resources`);
    const wh = services.body.data.find((r: { id: string }) => r.id === hooks.stripe);
    expect(wh.webhookUrl).toBe(`https://hooks.cb.test/api/hooks/${hooks.stripe}`);
    expect(JSON.stringify(services.body)).not.toContain(STRIPE_WHSEC);
    expect(bob.plain.STRIPE_WEBHOOK_SECRET).toMatch(/^whsec_/);
    expect(bob.plain.STRIPE_WEBHOOK_SECRET).not.toBe(cara.plain.STRIPE_WEBHOOK_SECRET);
    expect(bob.plain.RAZORPAY_WEBHOOK_SECRET).toBeTruthy();
    for (const real of [STRIPE_WHSEC, RZP_WHSEC, STRIPE_KEY, RZP_SECRET])
      expect(JSON.stringify(bob.plain)).not.toContain(real);
    bob.close();
    cara.close();
  });

  it("FR-WH-002 two developers paying at once: each event reaches only the device that created the PaymentIntent, verified by the Stripe SDK with that device's fake", async () => {
    const { envId, bob, cara, hooks } = await shop();
    const bobEvents = openEvents(base, bob.token, envId);
    const caraEvents = openEvents(base, cara.token, envId);
    await waitFor(() => bobEvents.of("ready").length && caraEvents.of("ready").length);
    const [bobPi, caraPi] = await Promise.all([bob.createPaymentIntent(), cara.createPaymentIntent()]);
    await waitFor(async () => (await WebhookOwnerModel.countDocuments()) >= 2 || undefined);

    const r1 = await postStripe(hooks.stripe, piEvent("evt_Bob0000001", bobPi.id));
    const r2 = await postStripe(hooks.stripe, piEvent("evt_Cara000001", caraPi.id));
    expect(r1.status).toBe(200);
    expect(r2.status).toBe(200);

    const bw = await waitFor(() => bobEvents.of("webhook")[0]);
    const cw = await waitFor(() => caraEvents.of("webhook")[0]);
    expect(bw).toMatchObject({
      provider: "stripe",
      type: "payment_intent.succeeded",
      path: "/webhooks/stripe",
    });
    const headers = bw.headers as Record<string, string>;
    const event = Stripe.webhooks.constructEvent(
      decode(bw),
      headers["stripe-signature"] ?? "",
      bob.plain.STRIPE_WEBHOOK_SECRET ?? "",
    );
    expect(event.id).toBe("evt_Bob0000001");
    // Cara's fake cannot verify Bob's delivery, and the real secret is never sent.
    expect(() =>
      Stripe.webhooks.constructEvent(
        decode(bw),
        headers["stripe-signature"] ?? "",
        cara.plain.STRIPE_WEBHOOK_SECRET ?? "",
      ),
    ).toThrow();
    expect(JSON.stringify(bobEvents.events)).not.toContain(STRIPE_WHSEC);
    expect(JSON.parse(decode(cw).toString()).id).toBe("evt_Cara000001");
    await new Promise((r) => setTimeout(r, 200));
    expect(bobEvents.of("webhook")).toHaveLength(1);
    expect(caraEvents.of("webhook")).toHaveLength(1);

    expect((await ack(bob.token, bw.deliveryId)).status).toBe(200);
    expect(await WebhookDeliveryModel.findById(bw.deliveryId).lean()).toMatchObject({
      status: "delivered",
      appStatus: 200,
    });
    // Cara cannot ack Bob's delivery.
    expect((await ack(cara.token, bw.deliveryId)).status).toBe(404);
    await Promise.all([bobEvents.close(), caraEvents.close()]);
    bob.close();
    cara.close();
  });

  it("FR-WH-001 forged, stale and replayed webhooks: 400 / duplicate, nothing extra delivered", async () => {
    const { envId, bob, cara, hooks } = await shop();
    const pi = await bob.createPaymentIntent();
    const forged = await postStripe(hooks.stripe, piEvent("evt_Forged0001", pi.id), "whsec_attacker");
    expect(forged.status).toBe(400);
    const body = JSON.stringify(piEvent("evt_Stale00001", pi.id));
    const stale = await fetch(`${base}/api/hooks/${hooks.stripe}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "stripe-signature": stripeSign(body, STRIPE_WHSEC, Math.floor(Date.now() / 1000) - 600),
      },
      body,
    });
    expect(stale.status).toBe(400);
    // A developer's own fake secret cannot inject a webhook either.
    const withFake = await postStripe(
      hooks.stripe,
      piEvent("evt_Fake000001", pi.id),
      bob.plain.STRIPE_WEBHOOK_SECRET,
    );
    expect(withFake.status).toBe(400);
    expect(await WebhookEventModel.countDocuments()).toBe(0);

    const first = await postStripe(hooks.stripe, piEvent("evt_Retry00001", pi.id));
    const retry = await postStripe(hooks.stripe, piEvent("evt_Retry00001", pi.id));
    expect(first.status).toBe(200);
    expect(retry.status).toBe(200);
    expect((await retry.json()).data).toMatchObject({ duplicate: true });
    expect(await WebhookDeliveryModel.countDocuments()).toBe(1);
    const missing = await postStripe("6ac2cbc669c901c103b2ef99", piEvent("evt_Nope000001", pi.id));
    expect(missing.status).toBe(404);
    void envId;
    bob.close();
    cara.close();
  });

  it("FR-WH-002 follow-up events link back: charge.succeeded (ch_ of the owner's pi_) and Razorpay payment.captured (order_id) route to the creator", async () => {
    const { envId, bob, cara, hooks } = await shop();
    const bobEvents = openEvents(base, bob.token, envId);
    const caraEvents = openEvents(base, cara.token, envId);
    await waitFor(() => bobEvents.of("ready").length && caraEvents.of("ready").length);
    const pi = await bob.createPaymentIntent();
    const order = await cara.createOrder();
    await waitFor(async () => (await WebhookOwnerModel.countDocuments()) >= 2 || undefined);

    await postStripe(hooks.stripe, {
      id: "evt_Charge0001",
      type: "charge.succeeded",
      data: { object: { id: "ch_3NewCharge0001", object: "charge", payment_intent: pi.id } },
    });
    const rz = await postRazorpay(
      hooks.razorpay,
      {
        event: "payment.captured",
        payload: { payment: { entity: { id: "pay_Captured0001", order_id: order.id } } },
      },
      "RzEvt0001",
    );
    expect(rz.status).toBe(200);
    const charge = await waitFor(() => bobEvents.of("webhook")[0]);
    expect(charge.type).toBe("charge.succeeded");
    const captured = await waitFor(() => caraEvents.of("webhook")[0]);
    expect(captured).toMatchObject({
      provider: "razorpay",
      type: "payment.captured",
      path: "/webhooks/razorpay",
      port: 4000,
    });
    const h = captured.headers as Record<string, string>;
    expect(h["x-razorpay-event-id"]).toBe("RzEvt0001");
    expect(
      Razorpay.validateWebhookSignature(
        decode(captured).toString(),
        h["x-razorpay-signature"] ?? "",
        cara.plain.RAZORPAY_WEBHOOK_SECRET ?? "",
      ),
    ).toBe(true);
    // The charge is now Bob's too: a later charge.refunded naming only ch_ still reaches him.
    await postStripe(hooks.stripe, {
      id: "evt_Refund0001",
      type: "charge.refunded",
      data: { object: { id: "ch_3NewCharge0001", object: "charge" } },
    });
    await waitFor(() => bobEvents.of("webhook").length === 2);
    expect(caraEvents.of("webhook")).toHaveLength(1);
    await Promise.all([bobEvents.close(), caraEvents.close()]);
    bob.close();
    cara.close();
  });

  it("FR-WH-003 offline device: the event waits and is delivered when its stream reconnects; app errors are retried", async () => {
    const { envId, bob, cara, hooks } = await shop();
    const pi = await bob.createPaymentIntent();
    await waitFor(async () => (await WebhookOwnerModel.countDocuments()) >= 1 || undefined);
    expect((await postStripe(hooks.stripe, piEvent("evt_Offline001", pi.id))).status).toBe(200);
    expect(await WebhookDeliveryModel.findOne().lean()).toMatchObject({ status: "pending" });

    const events = openEvents(base, bob.token, envId);
    const w = await waitFor(() => events.of("webhook")[0]);
    expect(JSON.parse(decode(w).toString()).id).toBe("evt_Offline001");
    // The app answered 500: retried with backoff (re-signed with a fresh timestamp).
    await ack(bob.token, w.deliveryId, { ok: false, status: 500, error: "app answered 500" });
    const failed = await WebhookDeliveryModel.findById(w.deliveryId).lean();
    expect(failed).toMatchObject({ status: "pending", attempts: 1, appStatus: 500 });
    await sweepWebhooks(new Date(Date.now() + 60_000));
    const again = await waitFor(() => events.of("webhook")[1]);
    expect(again.deliveryId).toBe(w.deliveryId);
    await ack(bob.token, w.deliveryId);
    expect(await WebhookDeliveryModel.findById(w.deliveryId).lean()).toMatchObject({ status: "delivered" });
    await events.close();
    bob.close();
    cara.close();
  });

  it("FR-WH-002 unmatched events are never broadcast; re-routed once the owner is known; opted-in listeners get the rest", async () => {
    const { envId, bob, cara, hooks } = await shop();
    const bobEvents = openEvents(base, bob.token, envId);
    const caraEvents = openEvents(base, cara.token, envId);
    await waitFor(() => bobEvents.of("ready").length && caraEvents.of("ready").length);

    // The event beats the owner record (or names an object created elsewhere).
    await postStripe(hooks.stripe, piEvent("evt_Early00001", "pi_3EarlyBird00001"));
    expect(await WebhookEventModel.findOne().lean()).toMatchObject({ routing: "unmatched" });
    await new Promise((r) => setTimeout(r, 150));
    expect(bobEvents.of("webhook")).toHaveLength(0);
    expect(caraEvents.of("webhook")).toHaveLength(0);
    // The owner becomes known (e.g. the gateway write landed): the next sweep routes it to Bob only.
    await WebhookOwnerModel.create({
      environmentId: envId,
      provider: "stripe",
      objectId: "pi_3EarlyBird00001",
      deviceId: bob.deviceId,
      userId: (await WebhookOwnerModel.db.collection("devices").findOne({}))?.userId,
      expiresAt: new Date(Date.now() + 86_400_000),
    });
    await sweepWebhooks(new Date(Date.now() + 3_000));
    const early = await waitFor(() => bobEvents.of("webhook")[0]);
    await ack(bob.token, early.deliveryId);
    expect(caraEvents.of("webhook")).toHaveLength(0);

    // Dashboard/CLI-made objects nobody owns: only devices that opted in with `cb webhooks listen`.
    expect(
      (
        await cli(app, cara.token).post("/api/agent/webhooks/listen", {
          projectId: "shop",
          env: "development",
          unmatched: true,
        })
      ).status,
    ).toBe(200);
    await postStripe(hooks.stripe, piEvent("evt_Nobody0001", "pi_3MadeInDashb001"));
    await sweepWebhooks(new Date(Date.now() + 30_000));
    const got = await waitFor(() => caraEvents.of("webhook")[0]);
    expect(JSON.parse(decode(got).toString()).id).toBe("evt_Nobody0001");
    expect(new Set(bobEvents.of("webhook").map((w) => w.deliveryId)).size).toBe(1);
    expect(bobEvents.of("webhook")).toHaveLength(1); // acked: never pushed again
    await Promise.all([bobEvents.close(), caraEvents.close()]);
    bob.close();
    cara.close();
  });

  it("S3 a revoked device gets nothing; deliveries expire after 24 h and their bodies are gone", async () => {
    const { owner, envId, bob, cara, hooks } = await shop();
    const pi = await bob.createPaymentIntent();
    await waitFor(async () => (await WebhookOwnerModel.countDocuments()) >= 1 || undefined);
    expect((await owner.delete(`/api/devices/${bob.deviceId}`)).status).toBe(200);
    await postStripe(hooks.stripe, piEvent("evt_Revoked001", pi.id));
    const events = openEvents(base, bob.token, envId);
    await new Promise((r) => setTimeout(r, 300));
    expect(events.of("webhook")).toHaveLength(0);
    await events.close();

    const cpi = await cara.createPaymentIntent();
    await waitFor(async () => (await WebhookOwnerModel.countDocuments()) >= 2 || undefined);
    await postStripe(hooks.stripe, piEvent("evt_Expire0001", cpi.id));
    await sweepWebhooks(new Date(Date.now() + 25 * 3_600_000));
    const d = await WebhookDeliveryModel.findOne({ deviceId: cara.deviceId }).lean();
    expect(d?.status).toBe("expired");
    const e = await WebhookEventModel.findOne({ eventId: "evt_Expire0001" }).select("+body").lean();
    expect(e?.body ?? null).toBeNull();
    bob.close();
    cara.close();
  });

  it("admins see recent webhook events with delivery status, never the body or a secret", async () => {
    const { owner, envId, bob, cara, hooks } = await shop();
    const pi = await bob.createPaymentIntent();
    await waitFor(async () => (await WebhookOwnerModel.countDocuments()) >= 1 || undefined);
    await postStripe(hooks.stripe, piEvent("evt_Listed0001", pi.id));
    const list = await owner.get(`/api/environments/${envId}/webhook-events`);
    expect(list.status).toBe(200);
    expect(list.body.data[0]).toMatchObject({
      eventId: "evt_Listed0001",
      type: "payment_intent.succeeded",
      provider: "stripe",
      routing: "matched",
      deliveries: [expect.objectContaining({ status: "pending", deviceName: "Bob-laptop" })],
    });
    expect(JSON.stringify(list.body)).not.toContain(STRIPE_WHSEC);
    expect(list.body.data[0].body).toBeUndefined();
    // Replay re-queues the event for its devices.
    const replay = await owner.post(`/api/webhook-events/${list.body.data[0].id}/replay`, {});
    expect(replay.status).toBe(200);
    bob.close();
    cara.close();
  });

  it("D9 webhook service settings: Stripe secrets must be whsec_, the target is a path only, replace is write-only", async () => {
    const { owner, envId, bob, cara, hooks } = await shop();
    const url = `/api/environments/${envId}/services`;
    const notWhsec = await owner.post(url, {
      key: "BAD_WH",
      resource: {
        kind: "webhook",
        provider: "stripe",
        path: "/x",
        signingSecret: "sk_test_notasigningsecret",
      },
    });
    expect(notWhsec.status).toBe(400);
    for (const path of ["http://evil.example/x", "evil.example/x", "//evil.example/x"]) {
      const r = await owner.post(url, {
        key: "BAD_PATH",
        resource: { kind: "webhook", provider: "razorpay", path, signingSecret: "rzp_whsec_abcdefgh" },
      });
      expect(r.status, path).toBe(400);
    }
    const patched = await owner.patch(`/api/resources/${hooks.stripe}`, {
      signingSecret: "whsec_ROTATED_SECRET_0001",
      path: "/api/stripe/hook",
      port: 3060,
      test: true,
    });
    expect(patched.status, JSON.stringify(patched.body)).toBe(200);
    expect(patched.body.data.config).toMatchObject({
      provider: "stripe",
      path: "/api/stripe/hook",
      port: 3060,
    });
    expect(JSON.stringify(patched.body)).not.toContain("ROTATED_SECRET");
    // The old real secret no longer verifies; the new one does. Device fakes stay the same (no app restart).
    const pi = await bob.createPaymentIntent();
    expect((await postStripe(hooks.stripe, piEvent("evt_OldSecret01", pi.id))).status).toBe(400);
    expect(
      (await postStripe(hooks.stripe, piEvent("evt_NewSecret01", pi.id), "whsec_ROTATED_SECRET_0001")).status,
    ).toBe(200);
    const boot = await cli(app, bob.token).get(
      `/api/agent/bootstrap?projectId=${(await owner.get(`/api/environments/${envId}`)).body.data.projectId}&env=development`,
    );
    expect(boot.body.data.plain.STRIPE_WEBHOOK_SECRET).toBe(bob.plain.STRIPE_WEBHOOK_SECRET);
    // A disabled webhook service stops accepting provider calls.
    await owner.patch(`/api/resources/${hooks.stripe}`, { disabled: true });
    const off = await postStripe(hooks.stripe, piEvent("evt_Disabled01", pi.id), "whsec_ROTATED_SECRET_0001");
    expect(off.status).toBe(404);
    bob.close();
    cara.close();
  });

  it("FR-WH-001 oversized bodies are refused before any work", async () => {
    const { bob, cara, hooks } = await shop();
    const big = JSON.stringify({ id: "evt_Big", pad: "x".repeat(1_100_000) });
    const r = await fetch(`${base}/api/hooks/${hooks.stripe}`, {
      method: "POST",
      headers: { "content-type": "application/json", "stripe-signature": stripeSign(big) },
      body: big,
    });
    expect(r.status).toBe(413);
    expect(await WebhookEventModel.countDocuments()).toBe(0);
    bob.close();
    cara.close();
  });

  describe("review fixes", () => {
    const rzpEvent = (orderId: string, payId: string) => ({
      entity: "event",
      account_id: "acc_BFQ7uQEaa7j2z7", // the same on every Razorpay event of the account
      event: "payment.captured",
      contains: ["payment"],
      payload: { payment: { entity: { id: payId, entity: "payment", order_id: orderId } } },
      created_at: Date.now(),
    });

    it("C1 the shared Razorpay account id never makes one developer the owner of everyone's events", async () => {
      const { envId, bob, cara, hooks } = await shop();
      const bobEvents = openEvents(base, bob.token, envId);
      const caraEvents = openEvents(base, cara.token, envId);
      await waitFor(() => bobEvents.of("ready").length && caraEvents.of("ready").length);
      const [co, bo] = [await cara.createOrder(), await bob.createOrder()];
      await waitFor(async () => (await WebhookOwnerModel.countDocuments()) >= 2 || undefined);
      await postRazorpay(hooks.razorpay, rzpEvent(co.id, "pay_CaraPaid00001"), "RzC1");
      await waitFor(() => caraEvents.of("webhook")[0]);
      await postRazorpay(hooks.razorpay, rzpEvent(bo.id, "pay_BobPaid000001"), "RzB1");
      await waitFor(() => bobEvents.of("webhook")[0]);
      await new Promise((r) => setTimeout(r, 200));
      expect(caraEvents.of("webhook")).toHaveLength(1);
      expect(bobEvents.of("webhook")).toHaveLength(1);
      expect(await WebhookOwnerModel.exists({ objectId: "acc_BFQ7uQEaa7j2z7" })).toBeNull();
      await Promise.all([bobEvents.close(), caraEvents.close()]);
      bob.close();
      cara.close();
    });

    it("I1 a customer another developer touched first does not pull them into this developer's payment", async () => {
      const { envId, bob, cara, hooks } = await shop();
      const caraEvents = openEvents(base, cara.token, envId);
      const bobEvents = openEvents(base, bob.token, envId);
      await waitFor(() => bobEvents.of("ready").length && caraEvents.of("ready").length);
      const pi = await bob.createPaymentIntent();
      await waitFor(async () => (await WebhookOwnerModel.countDocuments()) >= 1 || undefined);
      const caraUser = (
        await mongoose.connection.db
          ?.collection("devices")
          .findOne({ _id: new mongoose.Types.ObjectId(cara.deviceId) })
      )?.userId;
      await WebhookOwnerModel.create({
        environmentId: envId,
        provider: "stripe",
        objectId: "cus_SharedCust001",
        deviceId: cara.deviceId,
        userId: caraUser,
        expiresAt: new Date(Date.now() + 86_400_000),
      });
      await postStripe(hooks.stripe, {
        id: "evt_SharedCust01",
        type: "payment_intent.succeeded",
        data: { object: { id: pi.id, object: "payment_intent", customer: "cus_SharedCust001" } },
      });
      await waitFor(() => bobEvents.of("webhook")[0]);
      await new Promise((r) => setTimeout(r, 200));
      expect(caraEvents.of("webhook")).toHaveLength(0);
      await Promise.all([bobEvents.close(), caraEvents.close()]);
      bob.close();
      cara.close();
    });

    it("I3 Replay reaches the app again: the push carries a new generation", async () => {
      const { owner, envId, bob, cara, hooks } = await shop();
      const events = openEvents(base, bob.token, envId);
      await waitFor(() => events.of("ready").length);
      const pi = await bob.createPaymentIntent();
      await waitFor(async () => (await WebhookOwnerModel.countDocuments()) >= 1 || undefined);
      await postStripe(hooks.stripe, piEvent("evt_Replay00001", pi.id));
      const first = await waitFor(() => events.of("webhook")[0]);
      expect(first.generation).toBe(0);
      await ack(bob.token, first.deliveryId, { ok: true, status: 200, generation: 0 });
      const list = await owner.get(`/api/environments/${envId}/webhook-events`);
      await owner.post(`/api/webhook-events/${list.body.data[0].id}/replay`, {});
      const again = await waitFor(() => events.of("webhook")[1]);
      expect(again).toMatchObject({ deliveryId: first.deliveryId, generation: 1 });
      // A late ack for the old generation does not close the replay.
      await ack(bob.token, first.deliveryId, { ok: true, status: 200, generation: 0 });
      expect(await WebhookDeliveryModel.findById(first.deliveryId).lean()).toMatchObject({
        status: "pending",
      });
      await ack(bob.token, first.deliveryId, { ok: true, status: 200, generation: 1 });
      expect(await WebhookDeliveryModel.findById(first.deliveryId).lean()).toMatchObject({
        status: "delivered",
      });
      await events.close();
      bob.close();
      cara.close();
    });

    it("I4 'app not running' is not a failed attempt; starting the app asks for a redelivery right away", async () => {
      const { envId, bob, cara, hooks } = await shop();
      const events = openEvents(base, bob.token, envId);
      await waitFor(() => events.of("ready").length);
      const pi = await bob.createPaymentIntent();
      await waitFor(async () => (await WebhookOwnerModel.countDocuments()) >= 1 || undefined);
      await postStripe(hooks.stripe, piEvent("evt_NoApp000001", pi.id));
      const w = await waitFor(() => events.of("webhook")[0]);
      await ack(bob.token, w.deliveryId, { ok: false, noApp: true, error: "app not running", generation: 0 });
      expect(await WebhookDeliveryModel.findById(w.deliveryId).lean()).toMatchObject({
        status: "pending",
        attempts: 0,
      });
      const r = await cli(app, bob.token).post("/api/agent/webhooks/redeliver", {
        projectId: "shop",
        env: "development",
      });
      expect(r.status).toBe(200);
      expect(r.body.data).toMatchObject({ queued: 1 });
      await waitFor(() => events.of("webhook")[1]);
      await events.close();
      bob.close();
      cara.close();
    });

    it("M2 a captured Razorpay request replayed with a new event id is a duplicate", async () => {
      const { bob, cara, hooks } = await shop();
      const ev = rzpEvent("order_TjzYjwnTHlKoEy", "pay_Replayed0001");
      expect((await postRazorpay(hooks.razorpay, ev, "RzOrig")).status).toBe(200);
      const replayed = await postRazorpay(hooks.razorpay, ev, "RzForgedNewId");
      expect((await replayed.json()).data).toMatchObject({ duplicate: true });
      expect(await WebhookEventModel.countDocuments()).toBe(1);
      bob.close();
      cara.close();
    });

    it("M3 a temporary loss of access keeps the delivery waiting instead of dropping it", async () => {
      const { owner, envId, bob, cara, hooks } = await shop();
      const pi = await bob.createPaymentIntent();
      await waitFor(async () => (await WebhookOwnerModel.countDocuments()) >= 1 || undefined);
      const bobUser = (
        await mongoose.connection.db
          ?.collection("devices")
          .findOne({ _id: new mongoose.Types.ObjectId(bob.deviceId) })
      )?.userId?.toHexString();
      const grant = await GrantModel.findOne({ environmentId: envId, userId: bobUser }).lean();
      await postStripe(hooks.stripe, piEvent("evt_Paused00001", pi.id));
      const d = await WebhookDeliveryModel.findOne().lean();
      const { renderPush } = await import("../../src/services/webhook-delivery.service.js");
      expect((await owner.delete(`/api/grants/${String(grant?._id)}`)).status).toBe(200);
      const subject = {
        userId: bobUser ?? "",
        deviceId: bob.deviceId,
        environmentId: envId,
        projectId: "",
        orgId: "",
      };
      expect(await renderPush(String(d?._id), subject)).toBeUndefined();
      expect(await WebhookDeliveryModel.findById(d?._id).lean()).toMatchObject({ status: "pending" });
      bob.close();
      cara.close();
    });

    it("M8 two streams from one device: each webhook is pushed once (newest stream), and the older takes over when it closes", async () => {
      const { envId, bob, cara, hooks } = await shop();
      const older = openEvents(base, bob.token, envId);
      await waitFor(() => older.of("ready").length);
      const newer = openEvents(base, bob.token, envId);
      await waitFor(() => newer.of("ready").length);
      const pi = await bob.createPaymentIntent();
      await waitFor(async () => (await WebhookOwnerModel.countDocuments()) >= 1 || undefined);
      await postStripe(hooks.stripe, piEvent("evt_TwoStream01", pi.id));
      await waitFor(() => newer.of("webhook")[0]);
      await new Promise((r) => setTimeout(r, 200));
      expect(older.of("webhook")).toHaveLength(0);
      await newer.close();
      await postStripe(hooks.stripe, piEvent("evt_TwoStream02", pi.id));
      await waitFor(() => older.of("webhook").length === 2); // the first one (unacked) is re-sent too
      await older.close();
      bob.close();
      cara.close();
    });
  });
});
