export const PRODUCT_NAME = "cb";
export const SERVICE_NAME = "cb-backend";
export const SERVICE_VERSION = "0.0.0";
export const API_PREFIX = "/api";
export const CORRELATION_HEADER = "x-correlation-id";
export const SHUTDOWN_TIMEOUT_MS = 10_000;
export const JSON_BODY_LIMIT = "1mb";
/** Provider webhooks (Stripe caps payloads well below this). */
export const WEBHOOK_BODY_LIMIT = "1mb";
export const GRANT_SWEEP_INTERVAL_MS = 2_000;
/** Webhook re-routing, re-pushes and 24 h expiry (FR-WH-003). */
export const WEBHOOK_SWEEP_INTERVAL_MS = 2_000;

/** S10 / FR-CRY-006: failed logins allowed per email and per caller IP within the window, then 429 until it passes. */
export const LOGIN_MAX_FAILURES_PER_EMAIL = 10;
export const LOGIN_MAX_FAILURES_PER_IP = 30;
export const LOGIN_FAILURE_WINDOW_MS = 15 * 60_000;
