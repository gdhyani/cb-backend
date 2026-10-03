import net from "node:net";
import tls from "node:tls";
import { parseMongoUri } from "../../utils/connection-uri.js";
import { upstreamCa } from "../http/upstream.js";
import { connected } from "../stream-io.js";
import type { StreamAdapter } from "../types.js";
import { authenticateScramSha256 } from "./scram.js";

/**
 * §10.8 mongodb (M0): the app connects without credentials (directConnection to the agent);
 * the gateway opens the upstream connection, authenticates with SCRAM-SHA-256, then pipes.
 */
export const mongodbAdapter: StreamAdapter = async (client, ctx) => {
  const real = parseMongoUri(ctx.secret);
  const useTls = real.params.get("tls") === "true" || real.params.get("ssl") === "true";
  const upstream = useTls
    ? tls.connect({ host: real.host, port: real.port, servername: real.host, ca: upstreamCa() })
    : net.connect({ host: real.host, port: real.port });
  upstream.pause();
  await connected(upstream, useTls ? "secureConnect" : "connect", `mongodb ${real.host}:${real.port}`);
  client.on("close", () => upstream.destroy());
  upstream.on("close", () => client.destroy());
  upstream.on("error", () => client.destroy());
  if (real.username) {
    const authSource = real.params.get("authSource") ?? (real.database || "admin");
    await authenticateScramSha256(upstream, real.username, real.password ?? "", authSource);
  }
  client.pipe(upstream);
  upstream.pipe(client);
};
