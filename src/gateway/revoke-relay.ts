import type { Duplex, Readable } from "node:stream";
import type { AdapterHooks } from "./types.js";

export const REVOKED_TEXT = "cb: access revoked by admin";
/** A revoked tunnel waits at most this long for an in-flight upstream message to finish. */
const BOUNDARY_WAIT_MS = 1000;

/** Tracks message boundaries in a byte stream so an error is never spliced into the middle of a reply. */
export interface Framer {
  feed(chunk: Buffer): void;
  readonly atBoundary: boolean;
}

/** Messages with a fixed-size header that encodes the total message length. */
export class LengthFramer implements Framer {
  #header = Buffer.alloc(0);
  #remaining = 0;
  constructor(
    private readonly headerSize: number,
    /** Total message size (header included) from a complete header. */
    private readonly totalSize: (header: Buffer) => number,
    private readonly onHeader?: (header: Buffer) => void,
  ) {}

  feed(chunk: Buffer): void {
    let offset = 0;
    while (offset < chunk.length) {
      if (this.#remaining > 0) {
        const take = Math.min(this.#remaining, chunk.length - offset);
        this.#remaining -= take;
        offset += take;
        continue;
      }
      const need = this.headerSize - this.#header.length;
      const part = chunk.subarray(offset, offset + need);
      this.#header = Buffer.concat([this.#header, part]);
      offset += part.length;
      if (this.#header.length === this.headerSize) {
        this.onHeader?.(this.#header);
        this.#remaining = Math.max(0, this.totalSize(this.#header) - this.headerSize);
        this.#header = Buffer.alloc(0);
      }
    }
  }

  get atBoundary(): boolean {
    return this.#remaining === 0 && this.#header.length === 0;
  }
}

/** Line protocols (SMTP replies): a boundary is right after "\n". */
export class LineFramer implements Framer {
  #last = 0x0a;
  feed(chunk: Buffer): void {
    if (chunk.length) this.#last = chunk[chunk.length - 1] ?? this.#last;
  }
  get atBoundary(): boolean {
    return this.#last === 0x0a;
  }
}

/** Postgres backend messages: type byte + int32 length (length counts itself, not the type). */
export const postgresFramer = () => new LengthFramer(5, (h) => 1 + h.readInt32BE(1));

/** MySQL packets: 3-byte little-endian payload length + sequence id. */
export function mysqlFramer() {
  let seq = 0;
  const framer = new LengthFramer(
    4,
    (h) => 4 + h.readUIntLE(0, 3),
    (h) => {
      seq = h[3] ?? 0;
    },
  );
  return Object.assign(framer, { lastSeq: () => seq });
}

/**
 * Forwards upstream → client while tracking message boundaries, and registers a revoke hook that stops the
 * session cleanly: stop reading from the app, let an in-flight upstream message finish (bounded), write the
 * protocol-native error, then end the client side (FR-GW-007).
 */
export function relayWithRevocation(
  client: Duplex,
  upstream: Duplex,
  framer: Framer,
  hooks: AdapterHooks,
  errorFrame: () => Buffer | undefined,
  /** App→upstream bytes; defaults to the client itself (MongoDB passes its post-authentication stream). */
  source: Readable = client,
): void {
  source.pipe(upstream);
  let stopping: (() => void) | undefined;
  upstream.on("data", (chunk: Buffer) => {
    framer.feed(chunk);
    if (!client.write(chunk)) {
      upstream.pause();
      client.once("drain", () => upstream.resume());
    }
    if (stopping && framer.atBoundary) stopping();
  });
  upstream.on("end", () => client.end());

  hooks.onRevoke = () =>
    new Promise<void>((resolve) => {
      source.unpipe(upstream);
      source.pause();
      const finish = () => {
        stopping = undefined;
        upstream.pause();
        const frame = errorFrame();
        // Resolve once the frame is handed to the tunnel, so closing the tunnel cannot drop it.
        if (frame && !client.destroyed) client.write(frame, () => resolve());
        else resolve();
      };
      if (framer.atBoundary) return finish();
      stopping = finish;
      setTimeout(() => stopping?.(), BOUNDARY_WAIT_MS).unref();
    });
}
