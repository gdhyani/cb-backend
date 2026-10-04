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
  // Name the usual mistakes instead of a generic "invalid URI" (the URL parser rejects them without detail).
  const port = /^[a-z+]+:\/\/(?:[^@/]*@)?(?:\[[^\]]*\]|[^:/?#]*):(\d+)/i.exec(uri)?.[1];
  if (port !== undefined && (Number(port) < 1 || Number(port) > 65535))
    throw invalid(field, `port ${port} is out of range (1–65535)`);
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(uri))
    throw invalid(field, "must start with a scheme, e.g. mongodb://");
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    throw invalid(
      field,
      "is not a valid connection URI (check the host, port and URL-encode special characters in the password)",
    );
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

/** MySQL clients spell "use TLS" several ways; any of them makes the gateway use verified TLS upstream (FR-GW-004). */
export function mysqlWantsTls(params: URLSearchParams): boolean {
  const v = (key: string) => (params.get(key) ?? "").toLowerCase();
  return (
    ["true", "1", "required"].includes(v("ssl")) ||
    v("ssl").startsWith("{") ||
    v("tls") === "true" ||
    ["required", "verify_ca", "verify_identity"].includes(v("ssl-mode")) ||
    ["required", "verify_ca", "verify_identity", "require", "verify-ca", "verify-full"].includes(v("sslmode"))
  );
}

/** Appended to "insecure transport" refusals so admins know the one-line fix. */
export const MYSQL_TLS_HINT = "the server requires TLS: add ?ssl=true to the connection URI";

export function parseSmtpUri(uri: string, field = "connectionUri"): ParsedConnection {
  return parse(uri, ["smtp", "smtps"], 587, field);
}
