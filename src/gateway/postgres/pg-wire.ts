import type { Readable } from "node:stream";
import { readExact } from "../stream-io.js";

/** Postgres frontend/backend protocol v3 helpers (only what the gateway needs). */
export const SSL_REQUEST = 80877103;
export const GSSENC_REQUEST = 80877104;
export const CANCEL_REQUEST = 80877102;
export const PROTOCOL_V3 = 196608;

export async function readStartup(stream: Readable): Promise<{ code: number; raw: Buffer; body: Buffer }> {
  const head = await readExact(stream, 8);
  const length = head.readInt32BE(0);
  const rest = length > 8 ? await readExact(stream, length - 8) : Buffer.alloc(0);
  return { code: head.readInt32BE(4), raw: Buffer.concat([head, rest]), body: rest };
}

export async function readMessage(stream: Readable): Promise<{ type: string; body: Buffer }> {
  const head = await readExact(stream, 5);
  const length = head.readInt32BE(1);
  const body = length > 4 ? await readExact(stream, length - 4) : Buffer.alloc(0);
  return { type: String.fromCharCode(head[0] ?? 0), body };
}

export function parseStartupParams(body: Buffer): Record<string, string> {
  const parts = body.toString("utf8").split("\0");
  const params: Record<string, string> = {};
  for (let i = 0; i + 1 < parts.length; i += 2) if (parts[i]) params[parts[i] as string] = parts[i + 1] ?? "";
  return params;
}

export function startupMessage(params: Record<string, string>): Buffer {
  const body = Buffer.from(
    `${Object.entries(params)
      .map(([k, v]) => `${k}\0${v}\0`)
      .join("")}\0`,
  );
  const head = Buffer.alloc(8);
  head.writeInt32BE(8 + body.length, 0);
  head.writeInt32BE(PROTOCOL_V3, 4);
  return Buffer.concat([head, body]);
}

export function message(type: string, body: Buffer): Buffer {
  const head = Buffer.alloc(5);
  head.write(type, 0, "latin1");
  head.writeInt32BE(4 + body.length, 1);
  return Buffer.concat([head, body]);
}

export const cstring = (s: string) => Buffer.from(`${s}\0`);

export function authRequest(code: number, extra: Buffer = Buffer.alloc(0)): Buffer {
  const body = Buffer.alloc(4);
  body.writeInt32BE(code, 0);
  return message("R", Buffer.concat([body, extra]));
}

export function errorResponse(code: string, text: string): Buffer {
  return message(
    "E",
    Buffer.concat([
      cstring("SFATAL"),
      cstring("VFATAL"),
      cstring(`C${code}`),
      cstring(`M${text}`),
      Buffer.from([0]),
    ]),
  );
}

/** Extracts the "M" (message) field of an ErrorResponse body. */
export function errorText(body: Buffer): string {
  return (
    body
      .toString("utf8")
      .split("\0")
      .find((f) => f.startsWith("M"))
      ?.slice(1) ?? "upstream error"
  );
}
