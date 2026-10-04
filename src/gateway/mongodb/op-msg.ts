import type { Readable, Writable } from "node:stream";
import { BSON, type Document } from "bson";
import { readExact } from "../stream-io.js";
import { UpstreamError } from "../types.js";

const OP_MSG = 2013;
let nextRequestId = 1;

export function encodeOpMsg(doc: Document): Buffer {
  const body = BSON.serialize(doc);
  const header = Buffer.alloc(21);
  header.writeInt32LE(21 + body.length, 0);
  header.writeInt32LE(nextRequestId++, 4);
  header.writeInt32LE(0, 8);
  header.writeInt32LE(OP_MSG, 12);
  header.writeUInt32LE(0, 16);
  header.writeUInt8(0, 20);
  return Buffer.concat([header, body]);
}

/** Sends one command and reads its reply (single kind-0 section). */
export async function runCommand(socket: Readable & Writable, doc: Document): Promise<Document> {
  socket.write(encodeOpMsg(doc));
  const head = await readExact(socket, 16);
  const length = head.readInt32LE(0);
  const opCode = head.readInt32LE(12);
  const rest = await readExact(socket, length - 16);
  if (opCode !== OP_MSG) throw new UpstreamError(`mongodb replied with unexpected opcode ${opCode}`);
  if (rest.readUInt8(4) !== 0) throw new UpstreamError("mongodb reply has an unexpected section kind");
  const bodyLength = rest.readInt32LE(5);
  return BSON.deserialize(rest.subarray(5, 5 + bodyLength));
}
