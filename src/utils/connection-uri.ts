import { AppError } from "../errors/app-error.js";

export interface ParsedConnection {
  protocol: string;
  username?: string;
  password?: string;
  host: string;
  port: number;
  database: string;
  params: URLSearchParams;
}

function invalid(field: string, message: string): AppError {
  return new AppError("VALIDATION_FAILED", { details: [{ path: field, message }] });
}

/** Single-host URIs only in M0 (mongodb+srv and multi-host replica sets come later). */
function parse(uri: string, protocols: string[], defaultPort: number, field: string): ParsedConnection {
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    throw invalid(field, "is not a valid connection URI");
  }
  const protocol = url.protocol.replace(/:$/, "");
  if (!protocols.includes(protocol))
    throw invalid(field, `must start with ${protocols.map((p) => `${p}://`).join(" or ")}`);
  if (!url.hostname) throw invalid(field, "must include a host");
  return {
    protocol,
    username: url.username ? decodeURIComponent(url.username) : undefined,
    password: url.password ? decodeURIComponent(url.password) : undefined,
    host: url.hostname.replace(/^\[|\]$/g, ""),
    port: url.port ? Number(url.port) : defaultPort,
    database: decodeURIComponent(url.pathname.replace(/^\//, "")),
    params: url.searchParams,
  };
}

export function parseMongoUri(uri: string, field = "connectionUri"): ParsedConnection {
  if (uri.startsWith("mongodb+srv://"))
    throw invalid(field, "mongodb+srv is not supported yet; use a mongodb:// URI");
  if (/^mongodb:\/\/[^/]*,/.test(uri))
    throw invalid(field, "multi-host URIs are not supported yet; use the primary host");
  return parse(uri, ["mongodb"], 27017, field);
}

export function parseRedisUri(uri: string, field = "connectionUri"): ParsedConnection {
  return parse(uri, ["redis", "rediss"], 6379, field);
}

export function parsePostgresUri(uri: string, field = "connectionUri"): ParsedConnection {
  return parse(uri, ["postgres", "postgresql"], 5432, field);
}

export function parseMysqlUri(uri: string, field = "connectionUri"): ParsedConnection {
  return parse(uri, ["mysql"], 3306, field);
}

export function parseSmtpUri(uri: string, field = "connectionUri"): ParsedConnection {
  return parse(uri, ["smtp", "smtps"], 587, field);
}
