import { once } from "node:events";
import type { Readable } from "node:stream";
import { UpstreamError } from "./types.js";

/**
 * Resolves once the stream has new data, rejects if it ends, errors or closes first. Every listener is removed on
 * settle (no build-up across reads).
 */
function nextReadable(stream: Readable): Promise<void> {
  return new Promise((resolve, reject) => {
    const closed = () => done(new UpstreamError("upstream closed the connection"));
    const failed = (err: Error) => done(err instanceof UpstreamError ? err : new UpstreamError(err.message));
    const ready = () => done();
    function done(err?: Error) {
      stream.off("readable", ready);
      stream.off("end", closed);
      stream.off("close", closed);
      stream.off("error", failed);
      if (err) reject(err);
      else resolve();
    }
    stream.on("readable", ready);
    stream.once("end", closed);
    stream.once("close", closed);
    stream.once("error", failed);
  });
}

/**
 * Reads exactly n bytes in paused mode, so nothing is lost before a later pipe(). Drains whatever is buffered
 * (read() with no size) instead of read(n): read(n) on a partial frame leaves the bytes buffered, and every new
 * 'readable' listener on a non-empty buffer fires at once, so the loop would spin without ever yielding to I/O.
 */
export async function readExact(stream: Readable, n: number): Promise<Buffer> {
  if (n <= 0) return Buffer.alloc(0);
  const parts: Buffer[] = [];
  let have = 0;
  for (;;) {
    const chunk = stream.read() as Buffer | null;
    if (chunk) {
      parts.push(chunk);
      have += chunk.length;
      if (have >= n) {
        const all = parts.length === 1 ? chunk : Buffer.concat(parts, have);
        if (all.length > n) stream.unshift(all.subarray(n));
        return all.subarray(0, n);
      }
      continue;
    }
    if (stream.readableEnded || stream.destroyed) throw new UpstreamError("upstream closed the connection");
    await nextReadable(stream);
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
    await nextReadable(stream);
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
