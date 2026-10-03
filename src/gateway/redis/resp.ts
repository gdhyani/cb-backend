/** Minimal RESP helpers for the first commands of a Redis connection. */

export function encodeCommand(args: string[]): Buffer {
  const parts = [`*${args.length}\r\n`];
  for (const a of args) parts.push(`$${Buffer.byteLength(a)}\r\n${a}\r\n`);
  return Buffer.from(parts.join(""));
}

export type ParseResult =
  | { kind: "command"; args: string[]; length: number }
  | { kind: "incomplete" }
  | { kind: "other" };

/** Parses one RESP array of bulk strings from the start of buf. Inline commands are reported as "other". */
export function parseCommand(buf: Buffer): ParseResult {
  if (buf.length === 0) return { kind: "incomplete" };
  if (buf[0] !== 0x2a /* * */) return { kind: "other" };
  let pos = 0;
  const readLine = (): string | undefined => {
    const end = buf.indexOf("\r\n", pos);
    if (end < 0) return undefined;
    const line = buf.subarray(pos, end).toString("utf8");
    pos = end + 2;
    return line;
  };
  const header = readLine();
  if (header === undefined) return { kind: "incomplete" };
  const count = Number(header.slice(1));
  if (!Number.isInteger(count) || count < 0) return { kind: "other" };
  const args: string[] = [];
  for (let i = 0; i < count; i++) {
    const lenLine = readLine();
    if (lenLine === undefined) return { kind: "incomplete" };
    if (!lenLine.startsWith("$")) return { kind: "other" };
    const len = Number(lenLine.slice(1));
    if (buf.length < pos + len + 2) return { kind: "incomplete" };
    args.push(buf.subarray(pos, pos + len).toString("utf8"));
    pos += len + 2;
  }
  return { kind: "command", args, length: pos };
}
