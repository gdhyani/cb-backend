import { Transform, type TransformCallback } from "node:stream";

export const REDACTED = "[cb-redacted]";

/**
 * FR-GW-006: replaces the real secret (and its base64 form) in response bytes.
 * Keeps a tail of (longest needle - 1) bytes between chunks so split matches are still caught.
 */
export function createRedactor(secret: string): Transform {
  const needles = [secret, Buffer.from(secret).toString("base64")]
    .filter((n) => n.length >= 6)
    .map((n) => Buffer.from(n));
  const keep = Math.max(0, ...needles.map((n) => n.length - 1));
  let tail: Buffer = Buffer.alloc(0);

  const scrub = (buf: Buffer): Buffer => {
    let out: Buffer = buf;
    for (const needle of needles) {
      let i = out.indexOf(needle);
      while (i >= 0) {
        out = Buffer.concat([out.subarray(0, i), Buffer.from(REDACTED), out.subarray(i + needle.length)]);
        i = out.indexOf(needle, i + REDACTED.length);
      }
    }
    return out;
  };

  return new Transform({
    transform(chunk: Buffer, _enc, cb: TransformCallback) {
      const data = scrub(Buffer.concat([tail, chunk]));
      const cut = Math.max(0, data.length - keep);
      tail = data.subarray(cut);
      cb(null, data.subarray(0, cut));
    },
    flush(cb: TransformCallback) {
      cb(null, scrub(tail));
    },
  });
}
