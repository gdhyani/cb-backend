import { createHash, randomBytes } from "node:crypto";

/** Opaque bearer token: prefix + 32 random bytes (base64url). Only the hash is stored. */
export function newToken(prefix: string): string {
  return `${prefix}${randomBytes(32).toString("base64url")}`;
}

export function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

/** Human-friendly device user code, e.g. "KQWD-7HMX" (no ambiguous characters). */
export function newUserCode(): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const chars = Array.from(randomBytes(8), (b) => alphabet[b % alphabet.length]).join("");
  return `${chars.slice(0, 4)}-${chars.slice(4)}`;
}
