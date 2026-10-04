import net from "node:net";
import type { Duplex } from "node:stream";
import tls from "node:tls";
import { safeEqual } from "../../crypto/safe-equal.js";
import { fakeDbCredentials } from "../../services/fakes.service.js";
import { parseSmtpUri } from "../../utils/connection-uri.js";
import { upstreamCa } from "../http/upstream.js";
import { LineFramer, REVOKED_TEXT, relayWithRevocation } from "../revoke-relay.js";
import { connected, readLine } from "../stream-io.js";
import { type StreamAdapter, UpstreamError } from "../types.js";

const b64 = (s: string) => Buffer.from(s).toString("base64");
const unb64 = (s: string) => Buffer.from(s, "base64").toString("utf8");

/** Reads one (possibly multi-line) SMTP reply: "250-…" continues, "250 …" ends. */
async function readReply(stream: Duplex): Promise<{ code: number; lines: string[] }> {
  const lines: string[] = [];
  for (;;) {
    const line = await readLine(stream);
    lines.push(line);
    if (line.length < 4 || line[3] === " ") return { code: Number(line.slice(0, 3)), lines };
  }
}

async function command(
  stream: Duplex,
  line: string,
  expect: number[],
): Promise<{ code: number; lines: string[] }> {
  stream.write(`${line}\r\n`);
  const reply = await readReply(stream);
  if (!expect.includes(reply.code))
    throw new UpstreamError(
      `smtp upstream rejected "${line.split(" ")[0]}" (${reply.lines.at(-1) ?? reply.code})`,
    );
  return reply;
}

/** Opens the real SMTP session: greeting, EHLO, STARTTLS when offered (verified), AUTH with real credentials. */
async function openUpstream(uri: string): Promise<Duplex> {
  const real = parseSmtpUri(uri);
  const servername = net.isIP(real.host) ? undefined : real.host;
  let socket: Duplex =
    real.protocol === "smtps"
      ? tls.connect({ host: real.host, port: real.port, servername, ca: upstreamCa() })
      : net.connect({ host: real.host, port: real.port });
  socket.pause();
  await connected(
    socket,
    real.protocol === "smtps" ? "secureConnect" : "connect",
    `smtp ${real.host}:${real.port}`,
  );
  await readReply(socket);
  let ehlo = await command(socket, "EHLO cb-gateway", [250]);
  if (real.protocol === "smtp" && ehlo.lines.some((l) => /STARTTLS/i.test(l))) {
    await command(socket, "STARTTLS", [220]);
    const secure = tls.connect({ socket, servername, ca: upstreamCa() });
    secure.pause();
    await connected(secure, "secureConnect", `smtp ${real.host}:${real.port} (starttls)`);
    socket = secure;
    ehlo = await command(socket, "EHLO cb-gateway", [250]);
  }
  if (real.username) {
    await command(socket, `AUTH PLAIN ${b64(`\0${real.username}\0${real.password ?? ""}`)}`, [235]);
  }
  return socket;
}

/**
 * §10.8 smtp: speak SMTP to the app, accept AUTH PLAIN/LOGIN with the device's fake credentials,
 * then attach an authenticated upstream session and relay the rest (MAIL/RCPT/DATA…) unchanged.
 */
export const smtpAdapter: StreamAdapter = async (client: Duplex, ctx, hooks) => {
  const fake = fakeDbCredentials({
    deviceId: ctx.deviceId,
    environmentId: ctx.environmentId,
    resourceId: ctx.resource.id,
  });
  const say = (line: string) => client.write(`${line}\r\n`);
  const check = (user: string, pass: string) =>
    safeEqual(user, fake.username) && safeEqual(pass, fake.password);
  say("220 cb-gateway ESMTP ready");
  let authed = false;
  while (!authed) {
    const line = await readLine(client);
    const [verb = "", ...rest] = line.split(" ");
    const upper = verb.toUpperCase();
    if (upper === "EHLO") {
      say("250-cb-gateway");
      say("250-AUTH PLAIN LOGIN");
      say("250-8BITMIME");
      say("250 SMTPUTF8");
    } else if (upper === "HELO") say("250 cb-gateway");
    else if (upper === "NOOP" || upper === "RSET") say("250 OK");
    else if (upper === "QUIT") {
      say("221 Bye");
      client.end();
      return;
    } else if (upper === "AUTH" && rest[0]?.toUpperCase() === "PLAIN") {
      let payload = rest[1];
      if (!payload) {
        say("334 ");
        payload = await readLine(client);
      }
      const [, user = "", pass = ""] = unb64(payload).split("\0");
      authed = check(user, pass);
      say(authed ? "235 2.7.0 Authentication successful" : "535 5.7.8 Authentication credentials invalid");
    } else if (upper === "AUTH" && rest[0]?.toUpperCase() === "LOGIN") {
      let user = rest[1] ? unb64(rest[1]) : "";
      if (!user) {
        say(`334 ${b64("Username:")}`);
        user = unb64(await readLine(client));
      }
      say(`334 ${b64("Password:")}`);
      const pass = unb64(await readLine(client));
      authed = check(user, pass);
      say(authed ? "235 2.7.0 Authentication successful" : "535 5.7.8 Authentication credentials invalid");
    } else if (upper === "MAIL") say("530 5.7.0 Authentication required");
    else say("502 5.5.2 Command not recognized before authentication");
  }

  let upstream: Duplex;
  try {
    upstream = await openUpstream(ctx.secret);
  } catch (err) {
    say("421 4.7.0 cb: the gateway could not reach the mail server");
    client.end();
    throw err;
  }
  client.on("close", () => upstream.destroy());
  upstream.on("close", () => client.destroy());
  upstream.on("error", () => client.destroy());
  // FR-GW-007: a 421 reply (service closing) after the current reply line.
  relayWithRevocation(client, upstream, new LineFramer(), hooks, () =>
    Buffer.from(`421 4.7.0 ${REVOKED_TEXT}\r\n`),
  );
};
