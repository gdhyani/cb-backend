/**
 * FR-WH-002: which provider objects a request created and which objects an event is about. Device-bound fakes tell
 * the gateway who made each API call; these ids link the later webhook back to that device.
 */

/** Provider object ids look like `pi_3UMx…`, `order_Tjz…`: short lowercase prefix, then letters/digits only. */
const OBJECT_ID = /^([a-z]{2,10})_[A-Za-z0-9]{8,64}$/;
/** Stripe Checkout sessions carry their mode: `cs_test_…` / `cs_live_…` (their client secrets add `_secret_`). */
const CHECKOUT_ID = /^cs_(test|live)_[A-Za-z0-9]{8,80}$/;
/**
 * Never routing ids:
 * - keys, secrets and events (must not be stored; events are not objects): sk rk pk whsec rzp evt;
 * - accounts and apps every event of an account names: acct, ca (Stripe), acc (Razorpay `account_id`);
 * - catalog items shared by every developer's orders: price, prod, plan, coupon, promo, txr, item.
 */
const NOT_OBJECTS = new Set([
  "sk",
  "rk",
  "pk",
  "whsec",
  "rzp",
  "evt",
  "acct",
  "ca",
  "acc",
  "price",
  "prod",
  "plan",
  "coupon",
  "promo",
  "txr",
  "item",
]);

const MAX_IDS = 100;
const MAX_LIST = 20;

export function isObjectId(value: string): boolean {
  if (CHECKOUT_ID.test(value)) return true;
  const m = OBJECT_ID.exec(value);
  return Boolean(m?.[1] && !NOT_OBJECTS.has(m[1]));
}

function collect(value: unknown, depth: number, out: Set<string>, limit: number): void {
  if (out.size >= limit) return;
  if (typeof value === "string") {
    if (isObjectId(value)) out.add(value);
    return;
  }
  if (depth < 0 || value === null || typeof value !== "object") return;
  if (Array.isArray(value)) {
    if (value.length > MAX_LIST) return;
    for (const v of value) collect(v, depth - 1, out, limit);
    return;
  }
  for (const v of Object.values(value)) {
    if (out.size >= limit) return;
    collect(v, depth - 1, out, limit);
  }
}

const record = (v: unknown): Record<string, unknown> | undefined =>
  v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : undefined;

/** A create/update response: the object itself and its direct links (depth ≤ 2), long lists skipped. */
export function idsFromResponse(json: unknown): string[] {
  const out = new Set<string>();
  collect(json, 2, out, MAX_IDS);
  return [...out];
}

/** Ids named in an API path, e.g. /v1/payment_intents/pi_X/confirm. */
export function idsFromPath(path: string): string[] {
  return (path.split("?")[0] ?? "").split("/").filter(isObjectId);
}

/** Direct (one level) id links of an object: payment_intent, order_id, customer, subscription… */
function directLinks(obj: Record<string, unknown>): string[] {
  const out: string[] = [];
  for (const [k, v] of Object.entries(obj)) {
    if (k === "id") continue;
    if (typeof v === "string" && isObjectId(v)) out.push(v);
    const nested = record(v);
    if (nested && typeof nested.id === "string" && isObjectId(nested.id)) out.push(nested.id);
  }
  return out;
}

/**
 * What an event is about. `primary`: the object(s) the event describes (Stripe `data.object` / thin
 * `related_object`, Razorpay `payload.*.entity`); `linked`: their direct links. Routing prefers the owner of the
 * primary object and falls back to linked ids only when nobody owns it — so a shared customer or a second link never
 * sends one developer's event to another.
 */
export function eventTargets(json: unknown): { primary: string[]; linked: string[] } {
  const e = record(json) ?? {};
  const objects: Record<string, unknown>[] = [];
  const stripeObject = record(record(e.data)?.object);
  if (stripeObject) objects.push(stripeObject);
  const thin = record(e.related_object);
  if (thin) objects.push(thin);
  for (const part of Object.values(record(e.payload) ?? {})) {
    const entity = record(record(part)?.entity);
    if (entity) objects.push(entity);
  }
  const primary = new Set<string>();
  const linked = new Set<string>();
  for (const o of objects) if (typeof o.id === "string" && isObjectId(o.id)) primary.add(o.id);
  for (const o of objects) for (const id of directLinks(o)) if (!primary.has(id)) linked.add(id);
  return { primary: [...primary].slice(0, MAX_IDS), linked: [...linked].slice(0, MAX_IDS) };
}

/** Every object an event mentions (unknown payload shapes), capped. */
export function idsFromEvent(json: unknown): string[] {
  const out = new Set<string>();
  collect(json, 5, out, MAX_IDS);
  return [...out];
}
