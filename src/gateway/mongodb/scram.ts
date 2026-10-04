import { createHash } from "node:crypto";
import type { Readable, Writable } from "node:stream";
import { Binary } from "bson";
import { ScramClient } from "../sasl/scram-sha256.js";
import { UpstreamError } from "../types.js";
import { runCommand } from "./op-msg.js";

const payloadText = (doc: { payload?: Binary }) => Buffer.from(doc.payload?.buffer ?? []).toString("utf8");

export type MongoMechanism = "SCRAM-SHA-1" | "SCRAM-SHA-256";

/**
 * Picks the mechanism the way the drivers do (MongoDB auth spec): ask `hello` with saslSupportedMechs for this
 * user; SCRAM-SHA-256 when listed, otherwise SCRAM-SHA-1 (older servers and many Atlas users list only SHA-1).
 */
export async function negotiateMechanism(
  socket: Readable & Writable,
  username: string,
  authSource: string,
): Promise<MongoMechanism> {
  const hello = await runCommand(socket, {
    hello: 1,
    saslSupportedMechs: `${authSource}.${username}`,
    $db: "admin",
  });
  const mechs = Array.isArray(hello.saslSupportedMechs) ? (hello.saslSupportedMechs as unknown[]) : undefined;
  if (!mechs) return "SCRAM-SHA-1"; // servers before 4.0 do not answer saslSupportedMechs
  if (mechs.includes("SCRAM-SHA-256")) return "SCRAM-SHA-256";
  if (mechs.includes("SCRAM-SHA-1")) return "SCRAM-SHA-1";
  throw new UpstreamError(
    `mongodb user ${username} supports only ${mechs.map(String).join(", ")}; cb signs in with SCRAM-SHA-1 or SCRAM-SHA-256`,
  );
}

/** MongoDB's SCRAM-SHA-1 hashes the password as md5("user:mongo:password") before PBKDF2 (its legacy digest). */
const mongoSha1Password = (username: string, password: string) =>
  createHash("md5").update(`${username}:mongo:${password}`).digest("hex");

/** SCRAM over OP_MSG saslStart / saslContinue with the negotiated mechanism. */
export async function authenticateScram(
  socket: Readable & Writable,
  username: string,
  password: string,
  authSource: string,
  mechanism: MongoMechanism,
): Promise<void> {
  const scram =
    mechanism === "SCRAM-SHA-1"
      ? new ScramClient(username, mongoSha1Password(username, password), "sha1")
      : new ScramClient(username, password, "sha256");
  const start = await runCommand(socket, {
    saslStart: 1,
    mechanism,
    payload: new Binary(Buffer.from(scram.clientFirst())),
    autoAuthorize: 1,
    options: { skipEmptyExchange: true },
    $db: authSource,
  });
  if (start.ok !== 1)
    throw new UpstreamError(
      `mongodb authentication failed (${String(start.codeName ?? start.errmsg ?? "saslStart")})`,
    );
  const cont = await runCommand(socket, {
    saslContinue: 1,
    conversationId: start.conversationId,
    payload: new Binary(Buffer.from(scram.clientFinal(payloadText(start)))),
    $db: authSource,
  });
  if (cont.ok !== 1)
    throw new UpstreamError(
      `mongodb authentication failed (${String(cont.codeName ?? cont.errmsg ?? "saslContinue")})`,
    );
  scram.verifyServerFinal(payloadText(cont));
  if (!cont.done) {
    const final = await runCommand(socket, {
      saslContinue: 1,
      conversationId: start.conversationId,
      payload: new Binary(Buffer.alloc(0)),
      $db: authSource,
    });
    if (final.ok !== 1 || !final.done) throw new UpstreamError("mongodb did not complete authentication");
  }
}
