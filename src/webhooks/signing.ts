import { createHash, createHmac } from "node:crypto";
import { safeEqual } from "../crypto/safe-equal.js";

/** Webhook signature schemes, computed exactly as the providers (and their official SDKs) do. */
export const WEBHOOK_PROVIDERS = ["stripe", "razorpay"] as const;
export type WebhookProvider = (typeof WEBHOOK_PROVIDERS)[number];
export type HeaderMap = Record<string, string | undefined>;

/** Stripe's default tolerance in its SDKs. */
const STRIPE_TOLERANCE_S = 300;
const nowSeconds = () => Math.floor(Date.now() / 1000);
const hmacHex = (secret: string, data: string | Buffer) =>
  createHmac("sha256", secret).update(data).digest("hex");

/** FR-WH-001: is this webhook genuine for `secret`? (constant-time compare, S7) */
export function verifyWebhook(
  provider: WebhookProvider,
  secret: string,
  body: Buffer,
  headers: HeaderMap,
  now = nowSeconds(),
): boolean {
  if (provider === "razorpay") return safeEqual(headers["x-razorpay-signature"] ?? "", hmacHex(secret, body));
  const parts = (headers["stripe-signature"] ?? "").split(",").map((p) => {
    const i = p.indexOf("=");
    return [p.slice(0, i).trim(), p.slice(i + 1).trim()] as const;
  });
  const t = Number(parts.find(([k]) => k === "t")?.[1]);
  if (!Number.isInteger(t) || Math.abs(now - t) > STRIPE_TOLERANCE_S) return false;
  const expected = hmacHex(secret, `${t}.${body.toString("utf8")}`);
  // Not short-circuiting keeps the comparison time independent of which v1 matched.
  return parts.reduce((ok, [k, v]) => (k === "v1" && safeEqual(v, expected)) || ok, false);
}

/** Headers that make the provider's official SDK accept `body` when verified with `secret` (a device fake). */
export function signWebhook(
  provider: WebhookProvider,
  secret: string,
  body: Buffer,
  now = nowSeconds(),
): Record<string, string> {
  if (provider === "razorpay") return { "x-razorpay-signature": hmacHex(secret, body) };
  return { "stripe-signature": `t=${now},v1=${hmacHex(secret, `${now}.${body.toString("utf8")}`)}` };
}

/** The provider's own event id (dedupes provider retries); a body hash when the provider sends none. */
export function eventIdOf(provider: WebhookProvider, body: Buffer, headers: HeaderMap): string {
  if (provider === "razorpay" && headers["x-razorpay-event-id"]) return headers["x-razorpay-event-id"];
  if (provider === "stripe") {
    try {
      const id = (JSON.parse(body.toString("utf8")) as { id?: unknown }).id;
      if (typeof id === "string" && id.length > 0 && id.length <= 255) return id;
    } catch {
      // fall through to the hash
    }
  }
  return `sha256:${createHash("sha256").update(body).digest("hex")}`;
}
