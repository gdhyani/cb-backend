import type { Readable, Writable } from "node:stream";
import { Binary } from "bson";
import { ScramSha256Client } from "../sasl/scram-sha256.js";
import { UpstreamError } from "../types.js";
import { runCommand } from "./op-msg.js";

const payloadText = (doc: { payload?: Binary }) => Buffer.from(doc.payload?.buffer ?? []).toString("utf8");

/** SCRAM-SHA-256 over OP_MSG saslStart / saslContinue. */
export async function authenticateScramSha256(
  socket: Readable & Writable,
  username: string,
  password: string,
  authSource: string,
): Promise<void> {
  const scram = new ScramSha256Client(username, password);
  const start = await runCommand(socket, {
    saslStart: 1,
    mechanism: "SCRAM-SHA-256",
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
