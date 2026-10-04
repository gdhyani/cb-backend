import { constants, publicEncrypt } from "node:crypto";
import net from "node:net";
import type { Duplex } from "node:stream";
import { safeEqual } from "../../crypto/safe-equal.js";
import { fakeDbCredentials } from "../../services/fakes.service.js";
import { parseMysqlUri } from "../../utils/connection-uri.js";
import { mysqlFramer, REVOKED_TEXT, relayWithRevocation } from "../revoke-relay.js";
import { connected } from "../stream-io.js";
import { type StreamAdapter, UpstreamError } from "../types.js";
import {
  buildGreeting,
  buildHandshakeResponse,
  CAP,
  errPacket,
  nativePasswordToken,
  newScramble,
  packet,
  parseGreeting,
  parseHandshakeResponse,
  readPacket,
  scrambleFor,
  writePacket,
  xor,
} from "./mysql-wire.js";

const NATIVE = "mysql_native_password";

/** Completes the real login upstream; returns the upstream OK payload. */
async function authenticateUpstream(
  upstream: Duplex,
  seqStart: number,
  password: string,
  scramble: Buffer,
  plugin: string,
): Promise<Buffer> {
  let currentScramble = scramble;
  let currentPlugin = plugin;
  for (;;) {
    const { seq, payload } = await readPacket(upstream);
    const marker = payload[0];
    if (marker === 0x00) return payload;
    if (marker === 0xff)
      throw new UpstreamError(
        `mysql rejected the stored credentials (${payload.subarray(9).toString("utf8")})`,
      );
    if (marker === 0xfe) {
      // AuthSwitchRequest: plugin name, then a fresh scramble.
      const end = payload.indexOf(0, 1);
      currentPlugin = payload.subarray(1, end).toString("utf8");
      currentScramble = payload.subarray(end + 1, end + 21);
      writePacket(upstream, seq + 1, scrambleFor(currentPlugin, password, currentScramble));
      continue;
    }
    if (marker === 0x01 && payload[1] === 0x03) continue; // caching_sha2 fast auth succeeded; OK follows
    if (marker === 0x01 && payload[1] === 0x04) {
      // Full authentication without TLS: fetch the server's RSA public key and send the password encrypted.
      writePacket(upstream, seq + 1, Buffer.from([0x02]));
      const key = await readPacket(upstream);
      const pem = key.payload.subarray(1).toString("utf8");
      const encrypted = publicEncrypt(
        { key: pem, padding: constants.RSA_PKCS1_OAEP_PADDING },
        xor(Buffer.from(`${password}\0`), currentScramble),
      );
      writePacket(upstream, key.seq + 1, encrypted);
      continue;
    }
    throw new UpstreamError(
      `mysql sent an unexpected packet 0x${(marker ?? 0).toString(16)} during authentication (${currentPlugin}, seq ${seqStart})`,
    );
  }
}

/**
 * §10.8 mysql: connect upstream first, mirror its greeting to the app with our own scramble
 * (mysql_native_password), verify the device's fake password, then log in upstream with the real one.
 */
export const mysqlAdapter: StreamAdapter = async (client: Duplex, ctx, hooks) => {
  const real = parseMysqlUri(ctx.secret);
  const upstream = net.connect({ host: real.host, port: real.port });
  upstream.pause();
  await connected(upstream, "connect", `mysql ${real.host}:${real.port}`);
  client.on("close", () => upstream.destroy());
  upstream.on("close", () => client.destroy());
  upstream.on("error", () => client.destroy());

  const greeting = parseGreeting((await readPacket(upstream)).payload);
  const ourScramble = newScramble();
  writePacket(
    client,
    0,
    buildGreeting({
      ...greeting,
      capabilities: greeting.capabilities & ~CAP.SSL,
      scramble: ourScramble,
      plugin: NATIVE,
    }),
  );

  const response = await readPacket(client);
  const hs = parseHandshakeResponse(response.payload);
  let clientSeq = response.seq;
  let token = hs.authResponse;
  if (hs.plugin && hs.plugin !== NATIVE) {
    // Ask the client to answer our challenge with mysql_native_password.
    writePacket(
      client,
      clientSeq + 1,
      Buffer.concat([Buffer.from([0xfe]), Buffer.from(`${NATIVE}\0`), ourScramble, Buffer.from([0])]),
    );
    const switched = await readPacket(client);
    clientSeq = switched.seq;
    token = switched.payload;
  }
  const fake = fakeDbCredentials({
    deviceId: ctx.deviceId,
    environmentId: ctx.environmentId,
    resourceId: ctx.resource.id,
  });
  const expected = nativePasswordToken(fake.password, ourScramble);
  if (!safeEqual(hs.username, fake.username) || !safeEqual(token.toString("hex"), expected.toString("hex"))) {
    client.end(packet(clientSeq + 1, errPacket(1045, "28000", `Access denied for user '${hs.username}'`)));
    return;
  }

  const capabilities =
    (hs.capabilities & greeting.capabilities & ~CAP.SSL & ~CAP.CONNECT_ATTRS) |
    CAP.PLUGIN_AUTH |
    CAP.SECURE_CONNECTION |
    CAP.PROTOCOL_41;
  const database = hs.database ?? (real.database || undefined);
  writePacket(
    upstream,
    1,
    buildHandshakeResponse({
      capabilities: database ? capabilities | CAP.CONNECT_WITH_DB : capabilities & ~CAP.CONNECT_WITH_DB,
      maxPacket: hs.maxPacket,
      charset: hs.charset,
      username: real.username ?? "",
      authResponse: scrambleFor(greeting.plugin, real.password ?? "", greeting.scramble),
      database,
      plugin: greeting.plugin,
    }),
  );
  let ok: Buffer;
  try {
    ok = await authenticateUpstream(upstream, 1, real.password ?? "", greeting.scramble, greeting.plugin);
  } catch (err) {
    client.end(
      packet(
        clientSeq + 1,
        errPacket(2013, "HY000", "cb: the gateway could not authenticate to the database"),
      ),
    );
    throw err;
  }
  writePacket(client, clientSeq + 1, ok);
  // FR-GW-007: an ERR packet continuing the current sequence (1927 = connection killed).
  const framer = mysqlFramer();
  relayWithRevocation(client, upstream, framer, hooks, () =>
    packet((framer.lastSeq() + 1) & 0xff, errPacket(1927, "70100", REVOKED_TEXT)),
  );
};
