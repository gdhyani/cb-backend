import { Transform, type TransformCallback } from "node:stream";
import zlib from "node:zlib";

export const REDACTED = "[cb-redacted]";

/**
 * Every form a secret is redacted in (≥ 6 chars, so short values never shred a response): raw, base64, base64url,
 * URL-encoded (Location, query strings) and JSON-escaped (`/` → `\/`). I1.
 */
function needlesOf(secrets: string | string[]): string[] {
  const all = (Array.isArray(secrets) ? secrets : [secrets])
    .filter(Boolean)
    .flatMap((s) => [
      s,
      Buffer.from(s).toString("base64"),
      Buffer.from(s).toString("base64url"),
      encodeURIComponent(s),
      s.replace(/\//g, "\\/"),
    ])
    .filter((n) => n.length >= 6);
  // Longest first, so a longer form is replaced before a shorter one it contains.
  return [...new Set(all)].sort((a, b) => b.length - a.length);
}

/** I1: the Basic credential the gateway itself injected (base64 of `user:secret`) is as sensitive as the secret. */
export function injectedBasic(authorization: string | undefined): string[] {
  const m = /^Basic\s+(\S+)$/i.exec(authorization ?? "");
  return m?.[1] ? [m[1]] : [];
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

/**
 * C1 (FR-GW-006): redaction only works on plain bytes. A provider that compresses anyway (we never forward the app's
 * accept-encoding) is decompressed here; the app then gets an identity body without content-encoding/length.
 */
export function decoded(
  body: NodeJS.ReadableStream,
  headers: Record<string, string | string[]>,
): { body: NodeJS.ReadableStream; headers: Record<string, string | string[]> } {
  const enc = String(headers["content-encoding"] ?? "")
    .trim()
    .toLowerCase();
  const make =
    enc === "gzip" || enc === "x-gzip"
      ? zlib.createGunzip
      : enc === "deflate"
        ? zlib.createInflate
        : enc === "br"
          ? zlib.createBrotliDecompress
          : undefined;
  if (!make) return { body, headers };
  const { "content-encoding": _e, "content-length": _l, ...rest } = headers;
  return { body: body.pipe(make()), headers: rest };
}
