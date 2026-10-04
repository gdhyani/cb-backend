import { createHash, randomBytes } from "node:crypto";
import type { Readable, Writable } from "node:stream";
import { readExact } from "../stream-io.js";

/** MySQL client/server protocol helpers (handshake phase only). */
export const CAP = {
  CONNECT_WITH_DB: 0x8,
  PROTOCOL_41: 0x200,
  SSL: 0x800,
  SECURE_CONNECTION: 0x8000,
  PLUGIN_AUTH: 0x80000,
  CONNECT_ATTRS: 0x100000,
  PLUGIN_AUTH_LENENC: 0x200000,
} as const;

export async function readPacket(stream: Readable): Promise<{ seq: number; payload: Buffer }> {
  const head = await readExact(stream, 4);
  const length = head.readUIntLE(0, 3);
  return { seq: head[3] ?? 0, payload: length > 0 ? await readExact(stream, length) : Buffer.alloc(0) };
}

export function packet(seq: number, payload: Buffer): Buffer {
  const head = Buffer.alloc(4);
  head.writeUIntLE(payload.length, 0, 3);
  head[3] = seq & 0xff;
  return Buffer.concat([head, payload]);
}

export function writePacket(stream: Writable, seq: number, payload: Buffer): void {
  stream.write(packet(seq, payload));
}

function readCString(buf: Buffer, pos: number): [string, number] {
  const end = buf.indexOf(0, pos);
  const stop = end < 0 ? buf.length : end;
  return [buf.subarray(pos, stop).toString("utf8"), stop + 1];
}

function readLenEnc(buf: Buffer, pos: number): [number, number] {
  const first = buf[pos] ?? 0;
  if (first < 0xfb) return [first, pos + 1];
  if (first === 0xfc) return [buf.readUInt16LE(pos + 1), pos + 3];
  if (first === 0xfd) return [buf.readUIntLE(pos + 1, 3), pos + 4];
  return [Number(buf.readBigUInt64LE(pos + 1)), pos + 9];
}

function lenEnc(n: number): Buffer {
  if (n < 0xfb) return Buffer.from([n]);
  const b = Buffer.alloc(3);
  b[0] = 0xfc;
  b.writeUInt16LE(n, 1);
  return b;
}

export interface Greeting {
  serverVersion: string;
  connectionId: number;
  capabilities: number;
  charset: number;
  status: number;
  scramble: Buffer;
  plugin: string;
}

export function parseGreeting(p: Buffer): Greeting {
  let pos = 1;
  const [serverVersion, afterVersion] = readCString(p, pos);
  pos = afterVersion;
  const connectionId = p.readUInt32LE(pos);
  pos += 4;
  const part1 = p.subarray(pos, pos + 8);
  pos += 9;
  const capLow = p.readUInt16LE(pos);
  pos += 2;
  const charset = p[pos] ?? 0;
  pos += 1;
  const status = p.readUInt16LE(pos);
  pos += 2;
  const capHigh = p.readUInt16LE(pos);
  pos += 2;
  const authLen = p[pos] ?? 0;
  pos += 11;
  const part2Len = Math.max(13, authLen - 8);
  const part2 = p.subarray(pos, pos + part2Len - 1);
  pos += part2Len;
  const [plugin] = readCString(p, pos);
  return {
    serverVersion,
    connectionId,
    capabilities: (capHigh << 16) | capLow,
    charset,
    status,
    scramble: Buffer.concat([part1, part2]),
    plugin: plugin || "mysql_native_password",
  };
}

export function buildGreeting(g: Greeting): Buffer {
  const caps = Buffer.alloc(4);
  caps.writeUInt32LE(g.capabilities >>> 0, 0);
  const id = Buffer.alloc(4);
  id.writeUInt32LE(g.connectionId, 0);
  const status = Buffer.alloc(2);
  status.writeUInt16LE(g.status, 0);
  return Buffer.concat([
    Buffer.from([0x0a]),
    Buffer.from(`${g.serverVersion}\0`),
    id,
    g.scramble.subarray(0, 8),
    Buffer.from([0]),
    caps.subarray(0, 2),
    Buffer.from([g.charset]),
    status,
    caps.subarray(2, 4),
    Buffer.from([g.scramble.length + 1]),
    Buffer.alloc(10),
    g.scramble.subarray(8),
    Buffer.from([0]),
    Buffer.from(`${g.plugin}\0`),
  ]);
}

export interface HandshakeResponse {
  capabilities: number;
  maxPacket: number;
  charset: number;
  username: string;
  authResponse: Buffer;
  database?: string;
  plugin?: string;
}

export function parseHandshakeResponse(p: Buffer): HandshakeResponse {
  const capabilities = p.readUInt32LE(0);
  const maxPacket = p.readUInt32LE(4);
  const charset = p[8] ?? 0;
  let pos = 32;
  const [username, afterUser] = readCString(p, pos);
  pos = afterUser;
  let authResponse: Buffer;
  if (capabilities & CAP.PLUGIN_AUTH_LENENC) {
    const [len, after] = readLenEnc(p, pos);
    authResponse = p.subarray(after, after + len);
    pos = after + len;
  } else if (capabilities & CAP.SECURE_CONNECTION) {
    const len = p[pos] ?? 0;
    authResponse = p.subarray(pos + 1, pos + 1 + len);
    pos += 1 + len;
  } else {
    const [str, after] = readCString(p, pos);
    authResponse = Buffer.from(str);
    pos = after;
  }
  let database: string | undefined;
  if (capabilities & CAP.CONNECT_WITH_DB) [database, pos] = readCString(p, pos);
  let plugin: string | undefined;
  if (capabilities & CAP.PLUGIN_AUTH) [plugin] = readCString(p, pos);
  return {
    capabilities,
    maxPacket,
    charset,
    username,
    authResponse,
    database: database || undefined,
    plugin,
  };
}

export function buildHandshakeResponse(
  r: Required<
    Pick<HandshakeResponse, "capabilities" | "maxPacket" | "charset" | "username" | "authResponse">
  > & { database?: string; plugin: string },
): Buffer {
  const head = Buffer.alloc(32);
  head.writeUInt32LE(r.capabilities >>> 0, 0);
  head.writeUInt32LE(r.maxPacket, 4);
  head[8] = r.charset;
  const auth =
    r.capabilities & CAP.PLUGIN_AUTH_LENENC
      ? Buffer.concat([lenEnc(r.authResponse.length), r.authResponse])
      : Buffer.concat([Buffer.from([r.authResponse.length]), r.authResponse]);
  return Buffer.concat([
    head,
    Buffer.from(`${r.username}\0`),
    auth,
    r.capabilities & CAP.CONNECT_WITH_DB ? Buffer.from(`${r.database ?? ""}\0`) : Buffer.alloc(0),
    Buffer.from(`${r.plugin}\0`),
  ]);
}

const sha1 = (...parts: Buffer[]) => createHash("sha1").update(Buffer.concat(parts)).digest();
const sha256 = (...parts: Buffer[]) => createHash("sha256").update(Buffer.concat(parts)).digest();
const xor = (a: Buffer, b: Buffer) => Buffer.from(a.map((v, i) => v ^ (b[i % b.length] ?? 0)));

/** mysql_native_password: SHA1(pw) XOR SHA1(scramble + SHA1(SHA1(pw))) */
export function nativePasswordToken(password: string, scramble: Buffer): Buffer {
  if (!password) return Buffer.alloc(0);
  const h1 = sha1(Buffer.from(password));
  return xor(h1, sha1(scramble.subarray(0, 20), sha1(h1)));
}

/** caching_sha2_password: SHA256(pw) XOR SHA256(SHA256(SHA256(pw)) + scramble) */
export function cachingSha2Token(password: string, scramble: Buffer): Buffer {
  if (!password) return Buffer.alloc(0);
  const h1 = sha256(Buffer.from(password));
  return xor(h1, sha256(sha256(h1), scramble.subarray(0, 20)));
}

export function scrambleFor(plugin: string, password: string, scramble: Buffer): Buffer {
  return plugin === "caching_sha2_password"
    ? cachingSha2Token(password, scramble)
    : nativePasswordToken(password, scramble);
}

/** 20 random printable bytes (some clients choke on NUL in the scramble). */
export function newScramble(): Buffer {
  return Buffer.from(Array.from(randomBytes(20), (b) => 0x21 + (b % 94)));
}

export function errPacket(code: number, state: string, text: string): Buffer {
  const head = Buffer.alloc(3);
  head[0] = 0xff;
  head.writeUInt16LE(code, 1);
  return Buffer.concat([head, Buffer.from(`#${state}${text}`)]);
}

export { xor };
