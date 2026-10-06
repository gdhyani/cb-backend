import { Transform, type TransformCallback } from "node:stream";

export const REDACTED = "[cb-redacted]";

/** Every form a secret is redacted in: raw and base64 (≥ 6 chars, so short values never shred a response). */
function needlesOf(secrets: string | string[]): string[] {
  return (Array.isArray(secrets) ? secrets : [secrets])
    .filter(Boolean)
    .flatMap((s) => [s, Buffer.from(s).toString("base64")])
    .filter((n) => n.length >= 6);
}

/** N3 (S8): header values get the same treatment as bodies — a provider may echo the key in a header or Location. */
export function redactHeaders(
  headers: Record<string, string | string[]>,
  secrets: string[],
): Record<string, string | string[]> {
  const needles = needlesOf(secrets);
  const scrub = (v: string) => needles.reduce((acc, n) => acc.split(n).join(REDACTED), v);
  return Object.fromEntries(
    Object.entries(headers).map(([k, v]) => [k, Array.isArray(v) ? v.map(scrub) : scrub(v)]),
  );
}

/**
 * FR-GW-006: replaces the real secret(s) (and their base64 form) in response bytes.
 * Keeps a tail of (longest needle - 1) bytes between chunks so split matches are still caught.
 */
export function createRedactor(secrets: string | string[]): Transform {
  const needles = needlesOf(secrets).map((n) => Buffer.from(n));
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
