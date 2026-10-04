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

export interface MongoTarget extends ParsedConnection {
  /** mongodb+srv: `hosts` holds the one SRV name, resolved by the gateway at connect time. */
  srv: boolean;
  hosts: { host: string; port: number }[];
}

/** §10.8 mongodb: single host, replica-set host lists and mongodb+srv (the gateway discovers the primary). */
export function parseMongoUri(uri: string, field = "connectionUri"): MongoTarget {
  const srv = uri.startsWith("mongodb+srv://");
  const m = /^(mongodb(?:\+srv)?:\/\/)((?:[^@/]*@)?)([^/?#]*)(.*)$/i.exec(uri);
  if (!m) return { ...parse(uri, ["mongodb"], 27017, field), srv: false, hosts: [] };
  const [, , auth = "", hostList = "", rest = ""] = m;
  const hostSpecs = hostList.split(",").filter(Boolean);
  if (hostSpecs.length === 0) throw invalid(field, "must include a host");
  if (srv && (hostSpecs.length > 1 || /:\d+$/.test(hostSpecs[0] ?? "")))
    throw invalid(field, "mongodb+srv takes one host name and no port");
  // Each host is validated through the single-host parser (port range, characters); credentials/options once.
  const hosts = hostSpecs.map((h) => {
    const one = parse(`mongodb://${h}`, ["mongodb"], 27017, field);
    return { host: one.host, port: one.port };
  });
  const first = parse(`mongodb://${auth}${hostSpecs[0]}${rest}`, ["mongodb"], 27017, field);
  return { ...first, protocol: srv ? "mongodb+srv" : "mongodb", srv, hosts };
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
