import { describe, expect, it } from "vitest";
import {
  isThinEvent,
  parseWebhookSecrets,
  secretsToTry,
  serializeWebhookSecrets,
} from "../../../src/webhooks/secrets.js";

describe("FR-WH-001 one webhook variable holds the snapshot and thin signing secrets", () => {
  it("reads a legacy single secret as the snapshot secret", () => {
    expect(parseWebhookSecrets("whsec_legacy123")).toEqual({ snapshot: "whsec_legacy123" });
  });

  it("round-trips both secrets and an empty (not yet connected) set", () => {
    const raw = serializeWebhookSecrets({ snapshot: "whsec_a1", thin: "whsec_b2" });
    expect(parseWebhookSecrets(raw)).toEqual({ snapshot: "whsec_a1", thin: "whsec_b2" });
    expect(parseWebhookSecrets(serializeWebhookSecrets({}))).toEqual({});
  });

  it("a Razorpay secret that happens to look like JSON stays a plain secret", () => {
    expect(parseWebhookSecrets('{"x":1}')).toEqual({ snapshot: '{"x":1}' });
  });

  it("tells thin events (v2.core.event) from snapshot events", () => {
    expect(isThinEvent({ object: "v2.core.event", related_object: { id: "pi_1" } })).toBe(true);
    expect(isThinEvent({ object: "event" })).toBe(false);
    expect(isThinEvent({})).toBe(false);
  });

  it("tries the matching destination's secret first, then the other, skipping missing ones", () => {
    const s = { snapshot: "whsec_s", thin: "whsec_t" };
    expect(secretsToTry(s, true)).toEqual(["whsec_t", "whsec_s"]);
    expect(secretsToTry(s, false)).toEqual(["whsec_s", "whsec_t"]);
    expect(secretsToTry({ thin: "whsec_t" }, false)).toEqual(["whsec_t"]);
    expect(secretsToTry({}, false)).toEqual([]);
  });
});
