import { createHmac } from "node:crypto";
import Razorpay from "razorpay";
import Stripe from "stripe";
import { describe, expect, it } from "vitest";
import { eventIdOf, signWebhook, verifyWebhook } from "../../../src/webhooks/signing.js";

const body = Buffer.from(JSON.stringify({ id: "evt_1Abc", type: "payment_intent.succeeded" }));
const stripeHeader = (secret: string, t: number, raw = body) =>
  `t=${t},v1=${createHmac("sha256", secret)
    .update(`${t}.${raw.toString("utf8")}`)
    .digest("hex")}`;

describe("FR-WH-001 webhook signatures (provider schemes, as the official SDKs check them)", () => {
  const now = 1_800_000_000;
  it("accepts a genuine Stripe signature and rejects a wrong secret, a changed body or a stale timestamp", () => {
    const h = { "stripe-signature": stripeHeader("whsec_real", now) };
    expect(verifyWebhook("stripe", "whsec_real", body, h, now)).toBe(true);
    expect(verifyWebhook("stripe", "whsec_other", body, h, now)).toBe(false);
    expect(verifyWebhook("stripe", "whsec_real", Buffer.from("{}"), h, now)).toBe(false);
    expect(verifyWebhook("stripe", "whsec_real", body, h, now + 301)).toBe(false);
    expect(verifyWebhook("stripe", "whsec_real", body, {}, now)).toBe(false);
  });

  it("accepts any v1 among several (Stripe rolling secrets)", () => {
    const good = stripeHeader("whsec_real", now).split(",")[1];
    const h = { "stripe-signature": `t=${now},v1=deadbeef,${good}` };
    expect(verifyWebhook("stripe", "whsec_real", body, h, now)).toBe(true);
  });

  it("accepts a genuine Razorpay signature and rejects a wrong one", () => {
    const sig = createHmac("sha256", "rzp_secret").update(body).digest("hex");
    expect(verifyWebhook("razorpay", "rzp_secret", body, { "x-razorpay-signature": sig })).toBe(true);
    expect(verifyWebhook("razorpay", "nope", body, { "x-razorpay-signature": sig })).toBe(false);
  });

  it("re-signed headers verify in the official Stripe SDK with the device's fake secret", () => {
    const headers = signWebhook("stripe", "whsec_fake_device", body);
    const event = Stripe.webhooks.constructEvent(
      body,
      headers["stripe-signature"] ?? "",
      "whsec_fake_device",
    );
    expect(event.id).toBe("evt_1Abc");
    expect(() =>
      Stripe.webhooks.constructEvent(body, headers["stripe-signature"] ?? "", "whsec_other"),
    ).toThrow();
  });

  it("re-signed headers verify in the official Razorpay SDK with the device's fake secret", () => {
    const headers = signWebhook("razorpay", "fake_rzp", body);
    expect(
      Razorpay.validateWebhookSignature(body.toString(), headers["x-razorpay-signature"] ?? "", "fake_rzp"),
    ).toBe(true);
  });

  it("event id: Stripe body id, Razorpay header, otherwise a body hash", () => {
    expect(eventIdOf("stripe", body, {})).toBe("evt_1Abc");
    expect(eventIdOf("razorpay", body, { "x-razorpay-event-id": "Rz123" })).toBe("Rz123");
    const hashed = eventIdOf("razorpay", body, {});
    expect(hashed).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(eventIdOf("razorpay", body, {})).toBe(hashed);
  });
});
