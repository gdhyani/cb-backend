import type { Readable, Writable } from "node:stream";
import { BSON, type Document } from "bson";
import { readExact } from "../stream-io.js";
import { UpstreamError } from "../types.js";

const OP_MSG = 2013;
let nextRequestId = 1;

/** `responseTo` set: a reply to that request (used for revocation errors). */
export function encodeOpMsg(doc: Document, responseTo = 0): Buffer {
  const body = BSON.serialize(doc);
  const header = Buffer.alloc(21);
  header.writeInt32LE(21 + body.length, 0);
  header.writeInt32LE(nextRequestId++, 4);
  header.writeInt32LE(responseTo, 8);
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

export const OP_QUERY = 2004;
/** Keep Long/Int32/Double wrappers so a decoded command re-encodes byte-for-byte in type (e.g. topologyVersion). */
const LOSSLESS = { promoteValues: false } as const;
export const OP_MSG_CODE = OP_MSG;

/** OP_MSG kind-0 body (first section) plus whatever sections follow, unchanged. */
export function decodeOpMsg(raw: Buffer): { flags: number; body: Document; rest: Buffer } {
  const flags = raw.readUInt32LE(16);
  if (raw.readUInt8(20) !== 0) throw new UpstreamError("OP_MSG must start with a kind-0 section");
  const len = raw.readInt32LE(21);
  return {
    flags,
    body: BSON.deserialize(raw.subarray(21, 21 + len), LOSSLESS),
    rest: raw.subarray(21 + len),
  };
}

/** Re-encodes an OP_MSG with a new body, keeping requestId, flags (minus checksum) and trailing sections. */
export function reencodeOpMsg(original: Buffer, body: Document): Buffer {
  const { flags, rest } = decodeOpMsg(original);
  const tail = (flags & 1) === 1 ? rest.subarray(0, rest.length - 4) : rest;
  const doc = BSON.serialize(body);
  const header = Buffer.alloc(21);
  header.writeInt32LE(21 + doc.length + tail.length, 0);
  header.writeInt32LE(original.readInt32LE(4), 4);
  header.writeInt32LE(original.readInt32LE(8), 8);
  header.writeInt32LE(OP_MSG, 12);
  header.writeUInt32LE(flags & ~1, 16);
  header.writeUInt8(0, 20);
  return Buffer.concat([header, doc, tail]);
}

/** OP_QUERY (legacy hello only): flags, cstring collection, skip, return, query doc, optional selector. */
export function decodeOpQuery(raw: Buffer): { query: Document; queryStart: number; queryEnd: number } {
  const nameEnd = raw.indexOf(0, 20);
  const queryStart = nameEnd + 1 + 8;
  const queryEnd = queryStart + raw.readInt32LE(queryStart);
  return { query: BSON.deserialize(raw.subarray(queryStart, queryEnd), LOSSLESS), queryStart, queryEnd };
}

export function reencodeOpQuery(original: Buffer, query: Document): Buffer {
  const { queryStart, queryEnd } = decodeOpQuery(original);
  const out = Buffer.concat([
    original.subarray(0, queryStart),
    BSON.serialize(query),
    original.subarray(queryEnd),
  ]);
  out.writeInt32LE(out.length, 0);
  return out;
}
