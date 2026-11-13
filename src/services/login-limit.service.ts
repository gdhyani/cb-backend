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
  const w = live(map, key, now);
  if (w) {
    w.failures += 1;
    return;
  }
  map.set(key, { failures: 1, endsAt: now + LOGIN_FAILURE_WINDOW_MS });
  if (map.size <= MAX_KEYS) return;
  for (const [k, v] of map) if (v.endsAt <= now) map.delete(k);
  // Still full (a spray of fresh emails or addresses): forget the oldest windows first (Map keeps insertion order).
  for (const k of map.keys()) {
    if (map.size <= MAX_KEYS) break;
    map.delete(k);
  }
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

/**
 * Called before the password is checked: refuses (returns the seconds to wait) when the email or address is at its
 * limit, otherwise counts this attempt as a failure up front, so parallel requests cannot all pass the check before
 * any of them is counted. `loginSucceeded` gives the attempt back.
 */
export function beginLoginAttempt(email: string, ip: string, now = Date.now()): number {
  const wait = loginRetryAfterSeconds(email, ip, now);
  if (wait > 0) return wait;
  recordLoginFailure(email, ip, now);
  return 0;
}

/** A correct password clears that email's failures and returns the address's reserved attempt. */
export function loginSucceeded(email: string, ip: string, now = Date.now()): void {
  byEmail.delete(emailKey(email));
  const w = live(byIp, ip, now);
  if (w) w.failures = Math.max(0, w.failures - 1);
}

/** Test isolation only: each test file starts with no failures recorded. */
export function clearLoginFailures(): void {
  byEmail.clear();
  byIp.clear();
}

/** How many emails and addresses are tracked (memory bound, S10). */
export function loginLimiterSize(): { emails: number; ips: number } {
  return { emails: byEmail.size, ips: byIp.size };
}
