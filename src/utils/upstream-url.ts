import net from "node:net";
import { z } from "zod";

/** D11: plain http is allowed only to addresses that never leave a private network. */
export function isPrivateHost(hostname: string): boolean {
  const h = hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (h === "localhost") return true;
  if (net.isIPv4(h)) {
    const [a = 0, b = 0] = h.split(".").map(Number);
    return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
  }
  if (net.isIPv6(h)) return h === "::1" || /^f[cd][0-9a-f]{2}:/.test(h);
  return false;
}

export const HttpsOnlyUrl = z.url().refine((u) => u.startsWith("https://"), "must be an https:// URL");

/** https:// anywhere; http:// only for private or loopback addresses (TLS verification is never relaxed). */
export const UpstreamUrl = z
  .url()
  .refine(
    (u) => u.startsWith("https://") || (u.startsWith("http://") && isPrivateHost(new URL(u).hostname)),
    "must be https:// (http:// only for private addresses such as 10.x, 192.168.x or localhost)",
  );
