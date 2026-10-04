import { describe, expect, it } from "vitest";
import { idsFromEvent, idsFromPath, idsFromResponse, isObjectId } from "../../../src/webhooks/routing.js";

describe("FR-WH-002 webhook routing ids (who caused this event?)", () => {
  it("recognises provider object ids and never keys, secrets or event ids", () => {
    for (const id of [
      "pi_3UMxhhEBiNeTEPDw1BbEbqwu",
      "ch_3UMxiQEBiNeTEPDw",
      "order_TjzYjwnTHlKoEy",
      "pay_Abcdef1234",
    ])
      expect(isObjectId(id), id).toBe(true);
    for (const s of [
      "sk_test_abcdefghijkl",
      "rk_test_abcdefghijkl",
      "pk_live_abcdefghijkl",
      "whsec_abcdefghijklmnop",
      "rzp_test_abcdefghijk",
      "evt_1Abcdefghijk",
      "pi_123_secret_abcdefgh",
      "payment_intent.succeeded",
      "pi_short",
      "hello world",
    ])
      expect(isObjectId(s), s).toBe(false);
  });

  it("collects the created object and its direct links from a create response, skipping long lists", () => {
    const res = {
      id: "pi_3UMxhhEBiNeTEPDw1BbEbqwu",
      object: "payment_intent",
      client_secret: "pi_3UMxhhEBiNeTEPDw1BbEbqwu_secret_zzzzzzzz",
      customer: "cus_Qabcdefgh12",
      latest_charge: { id: "ch_3UMxiQEBiNeTEPDw0n", deep: { deeper: { id: "re_Ignoredbecausedeep" } } },
      payment_method_types: ["card"],
      list: {
        data: Array.from({ length: 25 }, (_, i) => ({ id: `pm_Listitem${String(i).padStart(4, "0")}` })),
      },
    };
    expect(idsFromResponse(res).sort()).toEqual(
      ["ch_3UMxiQEBiNeTEPDw0n", "cus_Qabcdefgh12", "pi_3UMxhhEBiNeTEPDw1BbEbqwu"].sort(),
    );
  });

  it("collects ids from an API path (confirm/capture of an existing object)", () => {
    expect(idsFromPath("/v1/payment_intents/pi_3UMxhhEBiNeTEPDw1BbEbqwu/confirm?expand=x")).toEqual([
      "pi_3UMxhhEBiNeTEPDw1BbEbqwu",
    ]);
    expect(idsFromPath("/v1/orders/order_TjzYjwnTHlKoEy/payments")).toEqual(["order_TjzYjwnTHlKoEy"]);
    expect(idsFromPath("/v1/payment_intents")).toEqual([]);
  });

  it("collects candidate ids from Stripe snapshot, Stripe thin and Razorpay events", () => {
    const snapshot = {
      id: "evt_1X",
      data: { object: { id: "ch_3UMxiQEBiNeTEPDw0n", payment_intent: "pi_3UMxhhEBiNeTEPDw1BbEbqwu" } },
    };
    expect(idsFromEvent(snapshot)).toEqual(
      expect.arrayContaining(["ch_3UMxiQEBiNeTEPDw0n", "pi_3UMxhhEBiNeTEPDw1BbEbqwu"]),
    );
    const thin = {
      id: "evt_2",
      object: "v2.core.event",
      related_object: { id: "pi_3UMxhhEBiNeTEPDw1BbEbqwu" },
    };
    expect(idsFromEvent(thin)).toEqual(["pi_3UMxhhEBiNeTEPDw1BbEbqwu"]);
    const rzp = {
      event: "payment.captured",
      payload: { payment: { entity: { id: "pay_Abcdef1234", order_id: "order_TjzYjwnTHlKoEy" } } },
    };
    expect(idsFromEvent(rzp)).toEqual(expect.arrayContaining(["pay_Abcdef1234", "order_TjzYjwnTHlKoEy"]));
  });

  it("caps how many ids an event can name", () => {
    const many = {
      data: {
        object: Object.fromEntries(Array.from({ length: 300 }, (_, i) => [`k${i}`, `pi_Abcdefgh${i}`])),
      },
    };
    expect(idsFromEvent(many).length).toBeLessThanOrEqual(100);
  });
});

describe("FR-WH-002 which payment provider a service talks to", () => {
  it("uses the preset that made it, else the real API host; anything else is not tracked", async () => {
    const { paymentProviderOf } = await import("../../../src/services/webhook-owner.service.js");
    expect(paymentProviderOf({ provider: "stripe", upstreamUrl: "https://example.test" })).toBe("stripe");
    expect(paymentProviderOf({ upstreamUrl: "https://api.stripe.com" })).toBe("stripe");
    expect(paymentProviderOf({ upstreamUrl: "https://api.razorpay.com/v1" })).toBe("razorpay");
    expect(paymentProviderOf({ provider: "openai", upstreamUrl: "https://api.openai.com" })).toBeUndefined();
    expect(paymentProviderOf({ upstreamUrl: "not a url" })).toBeUndefined();
  });
});

describe("FR-WH-002 review: route on the event's own object, never on accounts or catalog items", () => {
  it("Razorpay payload: the entity ids are primary, its order link is linked, the account id is ignored", async () => {
    const { eventTargets } = await import("../../../src/webhooks/routing.js");
    const rzp = {
      entity: "event",
      account_id: "acc_BFQ7uQEaa7j2z7",
      event: "payment.captured",
      contains: ["payment"],
      payload: {
        payment: {
          entity: {
            id: "pay_Captured0001",
            entity: "payment",
            order_id: "order_TjzYjwnTHlKoEy",
            customer_id: null,
          },
        },
      },
      created_at: 1567674606,
    };
    expect(eventTargets(rzp)).toEqual({ primary: ["pay_Captured0001"], linked: ["order_TjzYjwnTHlKoEy"] });
  });

  it("Stripe snapshot: data.object is primary; direct links are linked; prices, products and accounts never route", async () => {
    const { eventTargets } = await import("../../../src/webhooks/routing.js");
    const invoice = {
      id: "evt_1",
      account: "acct_1Abcdefghijk",
      data: {
        object: {
          id: "in_1Abcdefghijkl",
          subscription: "sub_1Abcdefghijk",
          customer: "cus_Qabcdefgh12",
          application: "ca_Abcdefghijklmn",
          lines: { data: [{ price: { id: "price_1Abcdefghij", product: "prod_Abcdefghijk" } }] },
        },
      },
    };
    expect(eventTargets(invoice)).toEqual({
      primary: ["in_1Abcdefghijkl"],
      linked: ["sub_1Abcdefghijk", "cus_Qabcdefgh12"],
    });
  });

  it("Stripe Checkout sessions route (cs_test_/cs_live_), their client secrets never do", async () => {
    const { eventTargets, idsFromResponse, isObjectId } = await import("../../../src/webhooks/routing.js");
    expect(isObjectId("cs_test_a1B2c3D4e5F6g7H8")).toBe(true);
    expect(isObjectId("cs_live_a1B2c3D4e5F6g7H8")).toBe(true);
    expect(isObjectId("cs_test_a1B2c3D4_secret_x9")).toBe(false);
    expect(
      eventTargets({ data: { object: { id: "cs_test_a1B2c3D4e5F6g7H8", payment_intent: null } } }).primary,
    ).toEqual(["cs_test_a1B2c3D4e5F6g7H8"]);
    expect(idsFromResponse({ id: "cs_test_a1B2c3D4e5F6g7H8", object: "checkout.session" })).toEqual([
      "cs_test_a1B2c3D4e5F6g7H8",
    ]);
  });

  it("Stripe thin events: related_object is primary", async () => {
    const { eventTargets } = await import("../../../src/webhooks/routing.js");
    expect(
      eventTargets({ object: "v2.core.event", related_object: { id: "pi_3UMxhhEBiNeTEPDw1BbE" } }),
    ).toEqual({
      primary: ["pi_3UMxhhEBiNeTEPDw1BbE"],
      linked: [],
    });
  });

  it("create responses never claim catalog items or accounts", async () => {
    const { idsFromResponse } = await import("../../../src/webhooks/routing.js");
    expect(
      idsFromResponse({
        id: "sub_1Abcdefghijk",
        items: {
          data: [{ id: "si_Abcdefghijk1", price: { id: "price_1Abcdefghij", product: "prod_Abcdefghijk" } }],
        },
        plan: { id: "plan_Abcdefghijk" },
        account_id: "acc_BFQ7uQEaa7j2z7",
      }),
    ).toEqual(["sub_1Abcdefghijk"]); // si_ sits below the depth-2 limit; price/prod/plan/acc never count
  });
});
