import { createHash } from "node:crypto";
import net from "node:net";
import type { Duplex } from "node:stream";
import tls from "node:tls";
import { safeEqual } from "../../crypto/safe-equal.js";
import { fakeDbCredentials } from "../../services/fakes.service.js";
import { parsePostgresUri } from "../../utils/connection-uri.js";
import { upstreamCa } from "../http/upstream.js";
import { postgresFramer, REVOKED_TEXT, relayWithRevocation } from "../revoke-relay.js";
import { ScramSha256Client } from "../sasl/scram-sha256.js";
import { connected, readExact } from "../stream-io.js";
import { type StreamAdapter, UpstreamError } from "../types.js";
import {
  authRequest,
  CANCEL_REQUEST,
  cstring,
  errorResponse,
  errorText,
  GSSENC_REQUEST,
  message,
  parseStartupParams,
  readMessage,
  readStartup,
  SSL_REQUEST,
  startupMessage,
} from "./pg-wire.js";

const AUTH_OK = 0;
const AUTH_CLEARTEXT = 3;
const AUTH_MD5 = 5;
const AUTH_SASL = 10;
const AUTH_SASL_CONTINUE = 11;
const AUTH_SASL_FINAL = 12;

async function openUpstream(
  host: string,
  port: number,
  sslmode: string | null,
  caCert?: unknown,
): Promise<Duplex> {
  const socket = net.connect({ host, port });
  socket.pause();
  await connected(socket, "connect", `postgres ${host}:${port}`);
  if (!sslmode || sslmode === "disable") return socket;
  const req = Buffer.alloc(8);
  req.writeInt32BE(8, 0);
  req.writeInt32BE(SSL_REQUEST, 4);
  socket.write(req);
  const answer = (await readExact(socket, 1)).toString();
  if (answer !== "S") {
    if (sslmode === "prefer" || sslmode === "allow") return socket;
    throw new UpstreamError("postgres server does not offer TLS");
  }
  // Upstream TLS always verifies (FR-GW-004), whatever sslmode the stored URI uses.
  const secure = tls.connect({
    socket,
    servername: net.isIP(host) ? undefined : host,
    ca: upstreamCa(caCert),
  });
  secure.pause();
  await connected(secure, "secureConnect", `postgres ${host}:${port} (tls)`);
  return secure;
}

/** Authenticates upstream with the real credentials (cleartext, MD5 or SCRAM-SHA-256). */
async function authenticateUpstream(upstream: Duplex, user: string, password: string): Promise<void> {
  let scram: ScramSha256Client | undefined;
  for (;;) {
    const msg = await readMessage(upstream);
    if (msg.type === "E")
      throw new UpstreamError(`postgres rejected the stored credentials (${errorText(msg.body)})`);
    if (msg.type !== "R")
      throw new UpstreamError(`postgres sent an unexpected '${msg.type}' during authentication`);
    const code = msg.body.readInt32BE(0);
    if (code === AUTH_OK) return;
    if (code === AUTH_CLEARTEXT) upstream.write(message("p", cstring(password)));
    else if (code === AUTH_MD5) {
      const salt = msg.body.subarray(4, 8);
      const inner = createHash("md5")
        .update(password + user)
        .digest("hex");
      const outer = createHash("md5")
        .update(Buffer.concat([Buffer.from(inner), salt]))
        .digest("hex");
      upstream.write(message("p", cstring(`md5${outer}`)));
    } else if (code === AUTH_SASL) {
      const mechanisms = msg.body.subarray(4).toString("utf8").split("\0").filter(Boolean);
      if (!mechanisms.includes("SCRAM-SHA-256"))
        throw new UpstreamError(`postgres offers unsupported SASL mechanisms: ${mechanisms.join(", ")}`);
      scram = new ScramSha256Client("", password);
      const first = Buffer.from(scram.clientFirst());
      const len = Buffer.alloc(4);
      len.writeInt32BE(first.length, 0);
      upstream.write(message("p", Buffer.concat([cstring("SCRAM-SHA-256"), len, first])));
    } else if (code === AUTH_SASL_CONTINUE && scram) {
      upstream.write(message("p", Buffer.from(scram.clientFinal(msg.body.subarray(4).toString("utf8")))));
    } else if (code === AUTH_SASL_FINAL && scram) {
      scram.verifyServerFinal(msg.body.subarray(4).toString("utf8"));
    } else {
      throw new UpstreamError(`postgres requested unsupported authentication method ${code}`);
    }
  }
}

/**
 * §10.8 postgres: act as a Postgres server towards the app (no TLS, cleartext password = the device's
 * fake), then authenticate upstream with the real credentials and pipe the session.
 */
export const postgresAdapter: StreamAdapter = async (client: Duplex, ctx, hooks) => {
  const real = parsePostgresUri(ctx.secret);
  const sslmode = real.params.get("sslmode");

  let startup = await readStartup(client);
  while (startup.code === SSL_REQUEST || startup.code === GSSENC_REQUEST) {
    client.write("N");
    startup = await readStartup(client);
  }
  if (startup.code === CANCEL_REQUEST) {
    // Query cancel arrives on its own connection; BackendKeyData was relayed unchanged, so forward as-is.
    const upstream = await openUpstream(real.host, real.port, null);
    upstream.end(startup.raw);
    client.end();
    return;
  }
  const params = parseStartupParams(startup.body);

  client.write(authRequest(AUTH_CLEARTEXT));
  const reply = await readMessage(client);
  const presented = reply.type === "p" ? reply.body.toString("utf8").replace(/\0$/, "") : "";
  const fake = fakeDbCredentials({
    deviceId: ctx.deviceId,
    environmentId: ctx.environmentId,
    resourceId: ctx.resource.id,
  });
  if (!safeEqual(presented, fake.password) || !safeEqual(params.user ?? "", fake.username)) {
    client.end(errorResponse("28P01", `password authentication failed for user "${params.user ?? ""}"`));
    return;
  }

  const upstream = await openUpstream(real.host, real.port, sslmode, ctx.resource.config.caCert);
  client.on("close", () => upstream.destroy());
  upstream.on("close", () => client.destroy());
  upstream.on("error", () => client.destroy());
  const forwarded: Record<string, string> = {
    ...params,
    user: real.username ?? params.user ?? "",
    database: real.database || params.database || real.username || "",
  };
  upstream.write(startupMessage(forwarded));
  try {
    await authenticateUpstream(upstream, forwarded.user ?? "", real.password ?? "");
  } catch (err) {
    client.end(errorResponse("08004", "cb: the gateway could not authenticate to the database"));
    throw err;
  }
  client.write(authRequest(AUTH_OK));
  // FR-GW-007: on revocation the app gets a FATAL ErrorResponse at a message boundary.
  relayWithRevocation(client, upstream, postgresFramer(), hooks, () => errorResponse("57P01", REVOKED_TEXT));
};
