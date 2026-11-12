import {
  LOGIN_FAILURE_WINDOW_MS,
  LOGIN_MAX_FAILURES_PER_EMAIL,
  LOGIN_MAX_FAILURES_PER_IP,
} from "../constants.js";

/**
 * S10 / FR-CRY-006: failed-login limits per email and per caller IP. In memory, like the webhook flood guards: one
 * backend process (multi-instance state is post-MVP, §18). A window starts at the first failure and lasts
 * LOGIN_FAILURE_WINDOW_MS; at the limit every login for that email or IP is refused until the window ends.
 */
interface Window {
  failures: number;
  endsAt: number;
}
const byEmail = new Map<string, Window>();
const byIp = new Map<string, Window>();
const MAX_KEYS = 10_000;

function live(map: Map<string, Window>, key: string, now: number): Window | undefined {
  const w = map.get(key);
  if (w && w.endsAt <= now) {
    map.delete(key);
    return undefined;
  }
  return w;
}

function bump(map: Map<string, Window>, key: string, now: number): void {
  if (map.size > MAX_KEYS) for (const [k, w] of map) if (w.endsAt <= now) map.delete(k);
  const w = live(map, key, now);
  if (w) w.failures += 1;
  else map.set(key, { failures: 1, endsAt: now + LOGIN_FAILURE_WINDOW_MS });
}

const emailKey = (email: string) => email.trim().toLowerCase();

/** Seconds until this email and IP may try again; 0 when a login attempt is allowed. */
export function loginRetryAfterSeconds(email: string, ip: string, now = Date.now()): number {
  const blocked = [
    { w: live(byEmail, emailKey(email), now), max: LOGIN_MAX_FAILURES_PER_EMAIL },
    { w: live(byIp, ip, now), max: LOGIN_MAX_FAILURES_PER_IP },
  ].filter((x) => x.w && x.w.failures >= x.max);
  if (blocked.length === 0) return 0;
  const endsAt = Math.max(...blocked.map((x) => x.w?.endsAt ?? now));
  return Math.max(1, Math.ceil((endsAt - now) / 1000));
}

export function recordLoginFailure(email: string, ip: string, now = Date.now()): void {
  bump(byEmail, emailKey(email), now);
  bump(byIp, ip, now);
}

/** A correct password clears that email's failures (the IP's count stays: one address guessing many accounts). */
export function recordLoginSuccess(email: string): void {
  byEmail.delete(emailKey(email));
}

/** Test isolation only: each test file starts with no failures recorded. */
export function clearLoginFailures(): void {
  byEmail.clear();
  byIp.clear();
}
