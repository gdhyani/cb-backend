import net from "node:net";
import type { Duplex } from "node:stream";
import tls from "node:tls";
import { safeEqual } from "../../crypto/safe-equal.js";
import { fakeRedisCredentials } from "../../services/fakes.service.js";
import { parseRedisUri } from "../../utils/connection-uri.js";
import { upstreamCa } from "../http/upstream.js";
import { connected, readLine } from "../stream-io.js";
import { type StreamAdapter, UpstreamError } from "../types.js";
import { encodeCommand, parseCommand } from "./resp.js";

const WRONGPASS = "-WRONGPASS invalid username-password pair or user is disabled.\r\n";

/**
 * §10.8 redis: authenticate upstream with the real credentials, then intercept the client's
 * AUTH / HELLO … AUTH (verified against this device's fake) before switching to a raw pipe.
 */
export const redisAdapter: StreamAdapter = async (client: Duplex, ctx, hooks) => {
  const real = parseRedisUri(ctx.secret);
  const upstream =
    real.protocol === "rediss"
      ? tls.connect({ host: real.host, port: real.port, servername: real.host, ca: upstreamCa() })
      : net.connect({ host: real.host, port: real.port });
  upstream.pause();
  await connected(
    upstream,
    real.protocol === "rediss" ? "secureConnect" : "connect",
    `redis ${real.host}:${real.port}`,
  );
  client.on("close", () => upstream.destroy());
  upstream.on("close", () => client.destroy());
  upstream.on("error", () => client.destroy());

  if (real.password) {
    upstream.write(
      encodeCommand(real.username ? ["AUTH", real.username, real.password] : ["AUTH", real.password]),
    );
    const reply = await readLine(upstream);
    if (!reply.startsWith("+OK")) throw new UpstreamError("redis rejected the stored credentials");
  }

  const fake = fakeRedisCredentials({
    deviceId: ctx.deviceId,
    environmentId: ctx.environmentId,
    resourceId: ctx.resource.id,
  });
  const fakeOk = (user: string | undefined, pass: string) =>
    safeEqual(pass, fake.password) &&
    (user === undefined || user === "default" || safeEqual(user, fake.username));

  hooks.onRevoke = (reason) => client.write(`-ERR cb: ${reason}\r\n`);
  upstream.pipe(client);

  let buffer: Buffer = Buffer.alloc(0);
  const onData = (chunk: Buffer) => {
    buffer = Buffer.concat([buffer, chunk]);
    for (;;) {
      const parsed = parseCommand(buffer);
      if (parsed.kind === "incomplete") return;
      if (parsed.kind === "command") {
        const name = parsed.args[0]?.toUpperCase();
        if (name === "AUTH") {
          const [user, pass] =
            parsed.args.length >= 3
              ? [parsed.args[1], parsed.args[2] ?? ""]
              : [undefined, parsed.args[1] ?? ""];
          client.write(fakeOk(user, pass) ? "+OK\r\n" : WRONGPASS);
          buffer = buffer.subarray(parsed.length);
          continue;
        }
        if (name === "HELLO") {
          const args = [...parsed.args];
          const i = args.findIndex((a) => a.toUpperCase() === "AUTH");
          if (i >= 0) {
            if (!fakeOk(args[i + 1], args[i + 2] ?? "")) {
              client.write(WRONGPASS);
              buffer = buffer.subarray(parsed.length);
              continue;
            }
            args.splice(i, 3);
          }
          upstream.write(encodeCommand(args));
          buffer = buffer.subarray(parsed.length);
          continue;
        }
      }
      // First ordinary command: hand over to a raw pipe.
      client.off("data", onData);
      if (buffer.length > 0) upstream.write(buffer);
      client.pipe(upstream);
      return;
    }
  };
  client.on("data", onData);
};
