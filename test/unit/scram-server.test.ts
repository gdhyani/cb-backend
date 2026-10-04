import { createHash, createHmac, pbkdf2Sync, randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { ScramServer } from "../../src/gateway/mongodb/scram-server.js";

const material = {
  username: "cbu_abcdefgh",
  password: "p".repeat(32),
  salt: Buffer.alloc(16, 7),
  iterations: 4096,
};
const H = (b: Buffer) => createHash("sha256").update(b).digest();
const HMAC = (k: Buffer, s: string) => createHmac("sha256", k).update(s).digest();

/** RFC 7677 client side, written independently of the server under test. */
function clientExchange(server: ScramServer, user: string, password: string) {
  const cnonce = randomBytes(18).toString("base64");
  const clientFirstBare = `n=${user},r=${cnonce}`;
  const serverFirst = server.first(`n,,${clientFirstBare}`);
  const attrs = Object.fromEntries(serverFirst.split(",").map((p) => [p[0], p.slice(2)]));
  const salted = pbkdf2Sync(password, Buffer.from(attrs.s ?? "", "base64"), Number(attrs.i), 32, "sha256");
  const clientKey = HMAC(salted, "Client Key");
  const withoutProof = `c=biws,r=${attrs.r}`;
  const authMessage = `${clientFirstBare},${serverFirst},${withoutProof}`;
  const sig = HMAC(H(clientKey), authMessage);
  const proof = Buffer.from(clientKey.map((b, i) => b ^ (sig[i] ?? 0))).toString("base64");
  const result = server.final(`${withoutProof},p=${proof}`);
  const expectedServerSig = HMAC(HMAC(salted, "Server Key"), authMessage).toString("base64");
  return { result, expectedServerSig, nonceOk: (attrs.r ?? "").startsWith(cnonce) };
}

describe("ScramServer (S7, FR-CRY-002)", () => {
  it("S7 accepts the device's fake user and password and proves itself", () => {
    const { result, expectedServerSig, nonceOk } = clientExchange(
      new ScramServer(material),
      material.username,
      material.password,
    );
    expect(nonceOk).toBe(true);
    expect(result).toEqual({ ok: true, serverFinal: `v=${expectedServerSig}` });
  });
  it("S7 rejects a wrong password", () => {
    expect(clientExchange(new ScramServer(material), material.username, "x".repeat(32)).result).toEqual({
      ok: false,
    });
  });
  it("S7 rejects another user name with the right password", () => {
    expect(clientExchange(new ScramServer(material), "cbu_zzzzzzzz", material.password).result).toEqual({
      ok: false,
    });
  });
  it("rejects a final message whose nonce does not extend the server nonce", () => {
    const s = new ScramServer(material);
    s.first(`n,,n=${material.username},r=abc`);
    expect(s.final("c=biws,r=other,p=AAAA")).toEqual({ ok: false });
  });
});
