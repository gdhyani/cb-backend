import { createHash, createHmac, pbkdf2Sync, randomBytes, timingSafeEqual } from "node:crypto";
import { safeEqual } from "../../crypto/safe-equal.js";

export interface ScramMaterial {
  username: string;
  password: string;
  salt: Buffer;
  iterations: number;
}

const H = (b: Buffer) => createHash("sha256").update(b).digest();
const HMAC = (k: Buffer, s: string) => createHmac("sha256", k).update(s).digest();
const attrs = (msg: string): Record<string, string> =>
  Object.fromEntries(
    msg
      .split(",")
      .filter((p) => p[1] === "=")
      .map((p) => [p[0], p.slice(2)]),
  );

/** RFC 5802/7677 server side for one conversation; the stored password is the device's fake (S7). */
export class ScramServer {
  #clientFirstBare = "";
  #serverFirst = "";
  #nonce = "";
  #userOk = false;

  constructor(private readonly material: ScramMaterial) {}

  first(clientFirst: string): string {
    // gs2 header "n,," (no channel binding), then the bare message.
    this.#clientFirstBare = clientFirst.replace(/^[ny],[^,]*,/, "");
    const a = attrs(this.#clientFirstBare);
    const user = (a.n ?? "").replace(/=2C/g, ",").replace(/=3D/g, "=");
    this.#userOk = safeEqual(user, this.material.username);
    this.#nonce = `${a.r ?? ""}${randomBytes(24).toString("base64")}`;
    this.#serverFirst = `r=${this.#nonce},s=${this.material.salt.toString("base64")},i=${this.material.iterations}`;
    return this.#serverFirst;
  }

  final(clientFinal: string): { ok: true; serverFinal: string } | { ok: false } {
    const a = attrs(clientFinal);
    const withoutProof = clientFinal.replace(/,p=[^,]*$/, "");
    if (!this.#serverFirst || a.r !== this.#nonce || !a.p) return { ok: false };
    const salted = pbkdf2Sync(
      this.material.password,
      this.material.salt,
      this.material.iterations,
      32,
      "sha256",
    );
    const storedKey = H(HMAC(salted, "Client Key"));
    const authMessage = `${this.#clientFirstBare},${this.#serverFirst},${withoutProof}`;
    const signature = HMAC(storedKey, authMessage);
    const proof = Buffer.from(a.p, "base64");
    if (proof.length !== signature.length) return { ok: false };
    const clientKey = Buffer.from(proof.map((b, i) => b ^ (signature[i] ?? 0)));
    const passOk = timingSafeEqual(H(clientKey), storedKey);
    if (!(passOk && this.#userOk)) return { ok: false };
    return { ok: true, serverFinal: `v=${HMAC(HMAC(salted, "Server Key"), authMessage).toString("base64")}` };
  }
}
