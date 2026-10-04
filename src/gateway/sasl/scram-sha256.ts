import { createHash, createHmac, pbkdf2Sync, randomBytes, timingSafeEqual } from "node:crypto";
import { UpstreamError } from "../types.js";

const hmac = (key: Buffer, data: string) => createHmac("sha256", key).update(data).digest();

function fields(message: string): Record<string, string> {
  return Object.fromEntries(
    message.split(",").map((part) => {
      const i = part.indexOf("=");
      return [part.slice(0, i), part.slice(i + 1)];
    }),
  );
}

/** SCRAM-SHA-256 client (RFC 7677), protocol-agnostic. Used by the MongoDB and Postgres adapters. */
export class ScramSha256Client {
  readonly #password: string;
  readonly #nonce = randomBytes(24).toString("base64");
  readonly clientFirstBare: string;
  #authMessage = "";
  #salted: Buffer = Buffer.alloc(0);

  /** Postgres ignores the SCRAM user name (it uses the startup user); pass "" there. */
  constructor(username: string, password: string) {
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
    this.#salted = pbkdf2Sync(this.#password, Buffer.from(f.s, "base64"), Number(f.i), 32, "sha256");
    const clientKey = hmac(this.#salted, "Client Key");
    const storedKey = createHash("sha256").update(clientKey).digest();
    const withoutProof = `c=biws,r=${f.r}`;
    this.#authMessage = `${this.clientFirstBare},${serverFirst},${withoutProof}`;
    const signature = hmac(storedKey, this.#authMessage);
    const proof = Buffer.from(clientKey.map((b, i) => b ^ (signature[i] ?? 0)));
    return `${withoutProof},p=${proof.toString("base64")}`;
  }

  verifyServerFinal(serverFinal: string): void {
    const expected = hmac(hmac(this.#salted, "Server Key"), this.#authMessage);
    const received = Buffer.from(fields(serverFinal).v ?? "", "base64");
    if (received.length !== expected.length || !timingSafeEqual(received, expected)) {
      throw new UpstreamError("upstream server signature mismatch");
    }
  }
}
