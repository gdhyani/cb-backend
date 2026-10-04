import { type Duplex, PassThrough } from "node:stream";
import { fakeScramMaterial } from "../../services/fakes.service.js";
import { parseMongoUri } from "../../utils/connection-uri.js";
import { upstreamCa } from "../http/upstream.js";
import { LengthFramer, REVOKED_TEXT, relayWithRevocation } from "../revoke-relay.js";
import type { AdapterHooks, StreamAdapter } from "../types.js";
import { runAuthGate } from "./auth-gate.js";
import { connectPrimary, seedList } from "./discovery.js";
import { encodeOpMsg } from "./op-msg.js";
import { authenticateScramSha256 } from "./scram.js";

/**
 * §10.8 mongodb: the gateway finds the primary (single host, replica-set list or mongodb+srv), authenticates with
 * the real credential (SCRAM-SHA-256); the app authenticates to the gateway with its device's fake credential (S7),
 * then pipes.
 */
export const mongodbAdapter: StreamAdapter = async (client, ctx, hooks) => {
  const real = parseMongoUri(ctx.secret);
  const seeds = await seedList(real);
  const upstream = await connectPrimary(
    seeds.hosts,
    seeds.tls,
    seeds.tls ? upstreamCa(ctx.resource.config.caCert) : undefined,
  );
  client.on("close", () => upstream.destroy());
  upstream.on("close", () => client.destroy());
  upstream.on("error", () => client.destroy());
  if (real.username) {
    const authSource = seeds.params.get("authSource") ?? (real.database || "admin");
    await authenticateScramSha256(upstream, real.username, real.password ?? "", authSource);
  }
  const material = fakeScramMaterial({
    deviceId: ctx.deviceId,
    environmentId: ctx.environmentId,
    resourceId: ctx.resource.id,
  });
  relayMongo(client, upstream, hooks, () => runAuthGate(client, upstream, material));
};

/**
 * FR-GW-007 for MongoDB: replies must answer a request id, so on revocation every request still waiting for
 * a reply gets an OP_MSG error (code 13 Unauthorized) instead of a silently dropped connection.
 */
function relayMongo(
  client: Duplex,
  upstream: Duplex,
  hooks: AdapterHooks,
  gate: () => Promise<NodeJS.ReadableStream>,
): void {
  const outstanding = new Set<number>();
  // App→upstream bytes after authentication; replies (hello during the gate included) flow back from the start.
  const gated = new PassThrough();
  gate().then(
    (stream) => stream.pipe(gated),
    () => client.destroy(),
  );
  // App → MongoDB: remember request ids (header offset 4) as they pass.
  const requests = new LengthFramer(
    16,
    (h) => h.readInt32LE(0),
    (h) => outstanding.add(h.readInt32LE(4)),
  );
  gated.on("data", (chunk: Buffer) => requests.feed(chunk));
  // MongoDB → app: a reply's responseTo (offset 8) settles its request; exhaust replies keep it open (harmless).
  const replies = new LengthFramer(
    16,
    (h) => h.readInt32LE(0),
    (h) => outstanding.delete(h.readInt32LE(8)),
  );
  relayWithRevocation(
    client,
    upstream,
    replies,
    hooks,
    () => {
      const frames = [...outstanding].map((requestId) =>
        encodeOpMsg({ ok: 0, errmsg: REVOKED_TEXT, code: 13, codeName: "Unauthorized" }, requestId),
      );
      outstanding.clear();
      return frames.length ? Buffer.concat(frames) : undefined;
    },
    gated,
  );
}
