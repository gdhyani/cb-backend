import { createSign, createVerify, type KeyLike } from "node:crypto";

export type JwtAlg = "RS256" | "ES256";

export interface DecodedJwt {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
}

const b64url = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
// ES256 signatures in JWTs are raw r‖s (IEEE P1363), not DER.
const signOptions = (alg: JwtAlg) => (alg === "ES256" ? { dsaEncoding: "ieee-p1363" as const } : {});

export function signJwt(
  alg: JwtAlg,
  key: KeyLike,
  payload: Record<string, unknown>,
  header: Record<string, unknown> = {},
): string {
  const input = `${b64url({ alg, typ: "JWT", ...header })}.${b64url(payload)}`;
  const signature = createSign("SHA256")
    .update(input)
    .sign({ key: key as never, ...signOptions(alg) });
  return `${input}.${signature.toString("base64url")}`;
}

/** Returns the decoded token when the signature verifies with `key` under `alg`; null otherwise. */
export function verifyJwt(token: string, alg: JwtAlg, key: KeyLike): DecodedJwt | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [h, p, s] = parts as [string, string, string];
  try {
    const header = JSON.parse(Buffer.from(h, "base64url").toString()) as Record<string, unknown>;
    if (header.alg !== alg) return null;
    const ok = createVerify("SHA256")
      .update(`${h}.${p}`)
      .verify({ key: key as never, ...signOptions(alg) }, Buffer.from(s, "base64url"));
    if (!ok) return null;
    return { header, payload: JSON.parse(Buffer.from(p, "base64url").toString()) as Record<string, unknown> };
  } catch {
    return null;
  }
}
