/**
 * FR-WH-001: a webhook service's signing secrets. Stripe gives every destination its own secret, so one variable
 * (one cb URL) holds the snapshot destination's and the thin destination's. Stored as one encrypted string; a
 * plain string (older services, Razorpay) is the snapshot secret.
 */
export interface WebhookSecrets {
  snapshot?: string;
  thin?: string;
}

const MARK = "cbWebhookSecrets";

export function serializeWebhookSecrets(s: WebhookSecrets): string {
  return JSON.stringify({
    [MARK]: 1,
    ...(s.snapshot ? { snapshot: s.snapshot } : {}),
    ...(s.thin ? { thin: s.thin } : {}),
  });
}

export function parseWebhookSecrets(raw: string): WebhookSecrets {
  if (raw.startsWith("{")) {
    try {
      const o = JSON.parse(raw) as Record<string, unknown>;
      if (o[MARK] === 1) {
        const out: WebhookSecrets = {};
        if (typeof o.snapshot === "string" && o.snapshot) out.snapshot = o.snapshot;
        if (typeof o.thin === "string" && o.thin) out.thin = o.thin;
        return out;
      }
    } catch {
      // not ours: a secret that starts with "{"
    }
  }
  return raw ? { snapshot: raw } : {};
}

/** Stripe thin events (event destinations with a thin payload) carry `object: "v2.core.event"`. */
export function isThinEvent(json: Record<string, unknown>): boolean {
  return json.object === "v2.core.event";
}

/** The destination's own secret first; the other one too, so a secret pasted into the wrong field still works. */
export function secretsToTry(s: WebhookSecrets, thin: boolean): string[] {
  const order = thin ? [s.thin, s.snapshot] : [s.snapshot, s.thin];
  return order.filter((x): x is string => Boolean(x));
}
