import type { Duplex } from "node:stream";

/**
 * http/tls servers call a few net.Socket-only methods on accepted connections.
 * Tunnel streams are plain Duplexes, so give them harmless no-op versions.
 */
export function asSocketLike(stream: Duplex): Duplex {
  const s = stream as Duplex & Record<string, unknown>;
  s.setTimeout ??= () => stream;
  s.setNoDelay ??= () => stream;
  s.setKeepAlive ??= () => stream;
  s.remoteAddress ??= "127.0.0.1";
  return stream;
}
