import type { Duplex, Readable } from "node:stream";
import { PassThrough } from "node:stream";
import { Binary, type Document } from "bson";
import {
  decodeOpMsg,
  decodeOpQuery,
  encodeOpMsg,
  OP_MSG_CODE,
  OP_QUERY,
  reencodeOpMsg,
  reencodeOpQuery,
} from "./op-msg.js";
import { type ScramMaterial, ScramServer } from "./scram-server.js";

const HELLO = new Set(["hello", "ismaster", "isMaster"]);
/** MongoDB's maxMessageSizeBytes; anything larger (or smaller than a header) is not a real message. */
const MAX_MESSAGE = 48_000_000;
const STRIP = ["speculativeAuthenticate", "saslSupportedMechs", "compression"] as const;
const AUTH_FAILED = { ok: 0, errmsg: "Authentication failed.", code: 18, codeName: "AuthenticationFailed" };
const NEEDS_AUTH = { ok: 0, errmsg: "command requires authentication", code: 13, codeName: "Unauthorized" };

const commandName = (body: Document) => Object.keys(body)[0] ?? "";
const strip = (body: Document) => {
  const copy = { ...body };
  for (const k of STRIP) delete copy[k];
  return copy;
};
const payloadText = (p: unknown) =>
  Buffer.from(p instanceof Binary ? p.buffer : ((p ?? new Uint8Array()) as Uint8Array)).toString("utf8");

/**
 * §10.8 mongodb: the app authenticates to the gateway with its device's fake SCRAM-SHA-256 credential (S7).
 * Before that only hello/isMaster reach the (already authenticated) upstream, stripped of speculative auth,
 * SASL mechanism probing and compression. Monitoring connections never authenticate and stay in this phase.
 * Resolves with the app→upstream byte stream once the app has authenticated.
 */
export function runAuthGate(client: Duplex, upstream: Duplex, material: ScramMaterial): Promise<Readable> {
  return new Promise((resolve, reject) => {
    const out = new PassThrough();
    let buffer = Buffer.alloc(0);
    let scram: ScramServer | undefined;
    // start → (saslStart) await-proof → (proof ok) done | await-empty → (empty saslContinue) done
    let state: "start" | "await-proof" | "await-empty" | "done" = "start";
    let skipEmpty = false;

    const reply = (requestId: number, doc: Document) => client.write(encodeOpMsg(doc, requestId));
    const sasl = (requestId: number, done: boolean, text: string) =>
      reply(requestId, { conversationId: 1, done, payload: new Binary(Buffer.from(text)), ok: 1 });
    const fail = (requestId: number) => {
      client.off("data", onData);
      reply(requestId, AUTH_FAILED);
      client.end();
      reject(new Error("mongodb fake credential rejected"));
    };
    /** Untrusted bytes from any local process: a malformed frame closes this client only, never the gateway. */
    const abort = (why: string) => {
      client.off("data", onData);
      buffer = Buffer.alloc(0);
      client.destroy();
      reject(new Error(`mongodb client sent ${why}`));
    };

    const handle = (raw: Buffer): boolean => {
      const requestId = raw.readInt32LE(4);
      const opCode = raw.readInt32LE(12);
      if (opCode === OP_QUERY) {
        // Legacy opcodes are valid only for the initial handshake, and only as a command (`<db>.$cmd`):
        // on older servers an OP_QUERY on a data namespace is a find on the real, authenticated connection.
        const { collection, query } = decodeOpQuery(raw);
        if (!collection.endsWith(".$cmd") || !HELLO.has(commandName(query))) {
          abort("a legacy query that is not a handshake");
          return false;
        }
        upstream.write(reencodeOpQuery(raw, strip(query)));
        return true;
      }
      if (opCode !== OP_MSG_CODE) {
        reply(requestId, NEEDS_AUTH);
        return true;
      }
      const { body } = decodeOpMsg(raw);
      const name = commandName(body);
      if (HELLO.has(name)) {
        upstream.write(reencodeOpMsg(raw, strip(body)));
      } else if (name === "saslStart" && state === "start" && body.mechanism === "SCRAM-SHA-256") {
        scram = new ScramServer(material);
        skipEmpty = Boolean((body.options as { skipEmptyExchange?: boolean } | undefined)?.skipEmptyExchange);
        sasl(requestId, false, scram.first(payloadText(body.payload)));
        state = "await-proof";
      } else if (name === "saslContinue" && state === "await-proof" && scram) {
        const result = scram.final(payloadText(body.payload));
        if (!result.ok) {
          fail(requestId);
          return false;
        }
        sasl(requestId, skipEmpty, result.serverFinal);
        state = skipEmpty ? "done" : "await-empty";
      } else if (name === "saslContinue" && state === "await-empty") {
        sasl(requestId, true, "");
        state = "done";
      } else if (name === "saslStart" || name === "saslContinue") {
        fail(requestId);
        return false;
      } else {
        reply(requestId, NEEDS_AUTH);
      }
      return true;
    };

    const onData = (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      while (buffer.length >= 4) {
        const length = buffer.readInt32LE(0);
        if (length < 16 || length > MAX_MESSAGE) return abort(`a frame of invalid length ${length}`);
        if (buffer.length < length) return;
        const raw = buffer.subarray(0, length);
        buffer = buffer.subarray(length);
        let ok: boolean;
        try {
          ok = handle(raw);
        } catch {
          return abort("a malformed frame");
        }
        if (!ok) return;
        if (state === "done") {
          client.off("data", onData);
          if (buffer.length) out.write(buffer);
          client.pipe(out);
          resolve(out);
          return;
        }
      }
    };
    client.on("data", onData);
    client.once("close", () => reject(new Error("client closed before authenticating")));
  });
}
