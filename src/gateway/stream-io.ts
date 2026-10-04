import { once } from "node:events";
import type { Readable } from "node:stream";
import { UpstreamError } from "./types.js";

/** Reads exactly n bytes in paused mode, so nothing is lost before a later pipe(). */
export async function readExact(stream: Readable, n: number): Promise<Buffer> {
  for (;;) {
    const chunk = stream.read(n) as Buffer | null;
    if (chunk) return chunk;
    if (stream.readableEnded || stream.destroyed) throw new UpstreamError("upstream closed the connection");
    await Promise.race([
      once(stream, "readable"),
      once(stream, "end").then(() => {
        throw new UpstreamError("upstream closed the connection");
      }),
    ]);
  }
}

/** Reads one CRLF-terminated line; anything after it is pushed back. */
export async function readLine(stream: Readable): Promise<string> {
  let buf = Buffer.alloc(0);
  for (;;) {
    const chunk = stream.read() as Buffer | null;
    if (chunk) {
      buf = Buffer.concat([buf, chunk]);
      const i = buf.indexOf("\r\n");
      if (i >= 0) {
        const rest = buf.subarray(i + 2);
        if (rest.length > 0) stream.unshift(rest);
        return buf.subarray(0, i).toString("utf8");
      }
      continue;
    }
    if (stream.readableEnded || stream.destroyed) throw new UpstreamError("upstream closed the connection");
    await Promise.race([
      once(stream, "readable"),
      once(stream, "end").then(() => {
        throw new UpstreamError("upstream closed the connection");
      }),
    ]);
  }
}

export async function connected(
  socket: NodeJS.EventEmitter,
  event: "connect" | "secureConnect",
  what: string,
): Promise<void> {
  try {
    await once(socket, event);
  } catch (err) {
    throw new UpstreamError(`${what} unreachable (${(err as NodeJS.ErrnoException).code ?? "error"})`);
  }
}
