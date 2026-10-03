import { createHash, createHmac, pbkdf2Sync, randomBytes, timingSafeEqual } from "node:crypto";
import type { Readable, Writable } from "node:stream";
import { Binary } from "bson";
import { UpstreamError } from "../types.js";
import { runCommand } from "./op-msg.js";

const hmac = (key: Buffer, data: string) => createHmac("sha256", key).update(data).digest();
const escapeName = (name: string) => name.replace(/=/g, "=3D").replace(/,/g, "=2C");

function parseFields(message: string): Record<string, string> {
  return Object.fromEntries(
    message.split(",").map((part) => {
      const i = part.indexOf("=");
      return [part.slice(0, i), part.slice(i + 1)];
    }),
  );
}

const payloadText = (doc: { payload?: Binary }) => Buffer.from(doc.payload?.buffer ?? []).toString("utf8");

/** SCRAM-SHA-256 client (RFC 7677) over OP_MSG saslStart / saslContinue. ASCII passwords (SASLprep is identity). */
export async function authenticateScramSha256(
  socket: Readable & Writable,
  username: string,
  password: string,
  authSource: string,
): Promise<void> {
  const nonce = randomBytes(24).toString("base64");
  const clientFirstBare = `n=${escapeName(username)},r=${nonce}`;
  const start = await runCommand(socket, {
    saslStart: 1,
    mechanism: "SCRAM-SHA-256",
    payload: new Binary(Buffer.from(`n,,${clientFirstBare}`)),
    autoAuthorize: 1,
    options: { skipEmptyExchange: true },
    $db: authSource,
  });
  if (start.ok !== 1)
    throw new UpstreamError(
      `mongodb authentication failed (${String(start.codeName ?? start.errmsg ?? "saslStart")})`,
    );
  const serverFirst = payloadText(start);
  const fields = parseFields(serverFirst);
  if (!fields.r?.startsWith(nonce) || !fields.s || !fields.i)
    throw new UpstreamError("mongodb sent an invalid SCRAM challenge");

  const salted = pbkdf2Sync(password, Buffer.from(fields.s, "base64"), Number(fields.i), 32, "sha256");
  const clientKey = hmac(salted, "Client Key");
  const storedKey = createHash("sha256").update(clientKey).digest();
  const withoutProof = `c=biws,r=${fields.r}`;
  const authMessage = `${clientFirstBare},${serverFirst},${withoutProof}`;
  const signature = hmac(storedKey, authMessage);
  const proof = Buffer.from(clientKey.map((b, i) => b ^ (signature[i] ?? 0)));

  const cont = await runCommand(socket, {
    saslContinue: 1,
    conversationId: start.conversationId,
    payload: new Binary(Buffer.from(`${withoutProof},p=${proof.toString("base64")}`)),
    $db: authSource,
  });
  if (cont.ok !== 1)
    throw new UpstreamError(
      `mongodb authentication failed (${String(cont.codeName ?? cont.errmsg ?? "saslContinue")})`,
    );
  const serverFinal = parseFields(payloadText(cont));
  const expected = hmac(hmac(salted, "Server Key"), authMessage);
  const received = Buffer.from(serverFinal.v ?? "", "base64");
  if (received.length !== expected.length || !timingSafeEqual(received, expected)) {
    throw new UpstreamError("mongodb server signature mismatch");
  }
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
