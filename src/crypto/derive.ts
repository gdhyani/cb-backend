import { createHmac } from "node:crypto";

const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const BASE32 = "abcdefghijklmnopqrstuvwxyz234567";

export type GeneratedFormat =
  | "hex:32"
  | "hex:64"
  | "base64:32"
  | "base64url:32"
  | "alnum:32"
  | "alnum:48"
  | "uuid";
export const GENERATED_FORMATS: readonly GeneratedFormat[] = [
  "hex:32",
  "hex:64",
  "base64:32",
  "base64url:32",
  "alnum:32",
  "alnum:48",
  "uuid",
];

/** Deterministic byte stream from HMAC-SHA256(secret, parts…) in counter mode. */
function stream(secret: Buffer, parts: string[], length: number): Buffer {
  const out: Buffer[] = [];
  let total = 0;
  for (let counter = 0; total < length; counter++) {
    const block = createHmac("sha256", secret)
      .update(`${parts.join("\u0000")}\u0000${counter}`)
      .digest();
    out.push(block);
    total += block.length;
  }
  return Buffer.concat(out).subarray(0, length);
}

function fromAlphabet(bytes: Buffer, alphabet: string): string {
  return Array.from(bytes, (b) => alphabet[b % alphabet.length]).join("");
}

export function alnum(secret: Buffer, parts: string[], length: number): string {
  return fromAlphabet(stream(secret, parts, length), ALNUM);
}

export function base32(secret: Buffer, parts: string[], length: number): string {
  return fromAlphabet(stream(secret, parts, length), BASE32);
}

/** FR-CRY-003: per (user, environment, variable) personal value. */
export function deriveGenerated(secret: Buffer, parts: string[], format: GeneratedFormat): string {
  const [kind, n] = format.split(":") as [string, string | undefined];
  const size = Number(n ?? 0);
  switch (kind) {
    case "hex":
      return stream(secret, parts, size / 2).toString("hex");
    case "base64":
      return stream(secret, parts, size).toString("base64");
    case "base64url":
      return stream(secret, parts, size).toString("base64url");
    case "alnum":
      return alnum(secret, parts, size);
    default: {
      const h = stream(secret, parts, 16).toString("hex");
      return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-a${h.slice(17, 20)}-${h.slice(20, 32)}`;
    }
  }
}
