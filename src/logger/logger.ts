import winston from "winston";
import { SERVICE_NAME } from "../constants.js";
import { getContext } from "./context.js";

const SENSITIVE = /authorization|cookie|password|passwd|secret|token|api[-_]?key|private[-_]?key/i;
const REDACTED = "[redacted]";

/** Deep-copies a value replacing sensitive keys (S9). */
export function redact(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redact);
  if (value && typeof value === "object" && !(value instanceof Error)) {
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [k, SENSITIVE.test(k) ? REDACTED : redact(v)]),
    );
  }
  return value;
}

const addContext = winston.format((info) => {
  const ctx = getContext();
  if (ctx?.correlationId && !info.correlationId) info.correlationId = ctx.correlationId;
  if (ctx?.userId && !info.userId) info.userId = ctx.userId;
  for (const key of Object.keys(info)) {
    if (key !== "message" && key !== "level" && key !== "stack") info[key] = redact(info[key]);
  }
  return info;
});

const devLine = winston.format.printf((info) => {
  const corr = info.correlationId ? ` [${String(info.correlationId).slice(0, 8)}]` : "";
  const stack = info.stack ? `\n${String(info.stack)}` : "";
  return `${info.level}${corr} ${String(info.message)}${stack}`;
});

function createLogger(): winston.Logger {
  const isProd = process.env.NODE_ENV === "production";
  return winston.createLogger({
    level: process.env.LOG_LEVEL ?? "info",
    defaultMeta: { service: SERVICE_NAME },
    silent: process.env.NODE_ENV === "test" && process.env.LOG_IN_TESTS !== "1",
    format: isProd
      ? winston.format.combine(addContext(), winston.format.timestamp(), winston.format.json())
      : winston.format.combine(addContext(), winston.format.colorize({ level: true }), devLine),
    transports: [new winston.transports.Console()],
  });
}

export const logger = createLogger();
