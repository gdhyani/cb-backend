import { createHash, createHmac, pbkdf2Sync, randomBytes, timingSafeEqual } from "node:crypto";
import { UpstreamError } from "../types.js";

export type ScramHash = "sha1" | "sha256";
const KEY_LENGTH: Record<ScramHash, number> = { sha1: 20, sha256: 32 };

function fields(message: string): Record<string, string> {
  return Object.fromEntries(
    message.split(",").map((part) => {
      const i = part.indexOf("=");
      return [part.slice(0, i), part.slice(i + 1)];
    }),
  );
}

/**
 * SCRAM client (RFC 5802 SHA-1 / RFC 7677 SHA-256), protocol-agnostic. Used by the MongoDB and Postgres adapters.
 * The caller passes the password exactly as the server hashes it (MongoDB SHA-1 uses its own digest, see scram.ts).
 */
export class ScramClient {
  readonly #hash: ScramHash;
  readonly #password: string;
  readonly #nonce = randomBytes(24).toString("base64");
  readonly clientFirstBare: string;
  #authMessage = "";
  #salted: Buffer = Buffer.alloc(0);

  /** Postgres ignores the SCRAM user name (it uses the startup user); pass "" there. */
  constructor(username: string, password: string, hash: ScramHash = "sha256") {
    this.#hash = hash;
    this.#password = password;
    this.clientFirstBare = `n=${username.replace(/=/g, "=3D").replace(/,/g, "=2C")},r=${this.#nonce}`;
  }

  clientFirst(): string {
    return `n,,${this.clientFirstBare}`;
  }

  clientFinal(serverFirst: string): string {
    const f = fields(serverFirst);
    if (!f.r?.startsWith(this.#nonce) || !f.s || !f.i)
      throw new UpstreamError("upstream sent an invalid SCRAM challenge");
    const h = this.#hash;
    this.#salted = pbkdf2Sync(this.#password, Buffer.from(f.s, "base64"), Number(f.i), KEY_LENGTH[h], h);
    const clientKey = this.#hmac(this.#salted, "Client Key");
    const storedKey = createHash(h).update(clientKey).digest();
    const withoutProof = `c=biws,r=${f.r}`;
    this.#authMessage = `${this.clientFirstBare},${serverFirst},${withoutProof}`;
    const signature = this.#hmac(storedKey, this.#authMessage);
    const proof = Buffer.from(clientKey.map((b, i) => b ^ (signature[i] ?? 0)));
    return `${withoutProof},p=${proof.toString("base64")}`;
  }

  verifyServerFinal(serverFinal: string): void {
    const expected = this.#hmac(this.#hmac(this.#salted, "Server Key"), this.#authMessage);
    const received = Buffer.from(fields(serverFinal).v ?? "", "base64");
    if (received.length !== expected.length || !timingSafeEqual(received, expected)) {
      throw new UpstreamError("upstream server signature mismatch");
    }
  }

  #hmac(key: Buffer, data: string): Buffer {
    return createHmac(this.#hash, key).update(data).digest();
  }
}

/** SCRAM-SHA-256 (Postgres and modern MongoDB users). */
export class ScramSha256Client extends ScramClient {
  constructor(username: string, password: string) {
    super(username, password, "sha256");
  }
}
