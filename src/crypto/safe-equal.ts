import { createHash, timingSafeEqual } from "node:crypto";

/** Constant-time comparison; hashing first makes unequal lengths safe (S7). */
export function safeEqual(a: string, b: string): boolean {
  const ha = createHash("sha256").update(a).digest();
  const hb = createHash("sha256").update(b).digest();
  return timingSafeEqual(ha, hb) && a.length === b.length;
}
