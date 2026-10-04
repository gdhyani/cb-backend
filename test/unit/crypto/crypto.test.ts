import { X509Certificate } from "node:crypto";
import type { AddressInfo } from "node:net";
import tls from "node:tls";
import { describe, expect, it } from "vitest";
import { createCa, LeafCache, mintLeaf } from "../../../src/crypto/ca.js";
import { alnum, deriveGenerated } from "../../../src/crypto/derive.js";
import { decryptSecret, encryptSecret } from "../../../src/crypto/envelope.js";
import { safeEqual } from "../../../src/crypto/safe-equal.js";
import { hashToken, newToken, newUserCode } from "../../../src/crypto/tokens.js";

const KEY = Buffer.alloc(32, 7);
const SECRET = Buffer.alloc(32, 9);

describe("envelope encryption (FR-CRY-001)", () => {
  it("round-trips and never stores plaintext", () => {
    const enc = encryptSecret(KEY, "mongodb://admin:hunter2@db:27017");
    expect(JSON.stringify(enc)).not.toContain("hunter2");
    expect(decryptSecret(KEY, enc)).toBe("mongodb://admin:hunter2@db:27017");
  });

  it("fails with the wrong master key", () => {
    const enc = encryptSecret(KEY, "x");
    expect(() => decryptSecret(Buffer.alloc(32, 1), enc)).toThrow();
  });
});

describe("derivations (FR-CRY-002, FR-CRY-003)", () => {
  it("is deterministic per input and differs across devices (S7)", () => {
    expect(alnum(SECRET, ["dev1", "env", "res"], 32)).toBe(alnum(SECRET, ["dev1", "env", "res"], 32));
    expect(alnum(SECRET, ["dev1", "env", "res"], 32)).not.toBe(alnum(SECRET, ["dev2", "env", "res"], 32));
  });

  it("formats generated values", () => {
    expect(deriveGenerated(SECRET, ["u", "e", "v"], "hex:32")).toMatch(/^[0-9a-f]{32}$/);
    expect(Buffer.from(deriveGenerated(SECRET, ["u", "e", "v"], "base64:32"), "base64")).toHaveLength(32);
    expect(deriveGenerated(SECRET, ["u", "e", "v"], "alnum:48")).toMatch(/^[A-Za-z0-9]{48}$/);
    expect(deriveGenerated(SECRET, ["u", "e", "v"], "uuid")).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-a[0-9a-f]{3}-[0-9a-f]{12}$/,
    );
  });
});

describe("tokens", () => {
  it("creates prefixed random tokens and stable hashes", () => {
    const t = newToken("cbd_");
    expect(t).toMatch(/^cbd_[A-Za-z0-9_-]{43}$/);
    expect(hashToken(t)).toBe(hashToken(t));
    expect(newUserCode()).toMatch(/^[A-Z2-9]{4}-[A-Z2-9]{4}$/);
  });

  it("S7 compares in constant time", () => {
    expect(safeEqual("abc", "abc")).toBe(true);
    expect(safeEqual("abc", "abd")).toBe(false);
    expect(safeEqual("a", "abc")).toBe(false);
  });
});

describe("org CA (FR-CRY-005)", () => {
  it("mints leaves that verify against the org CA only", async () => {
    const ca = await createCa("cb test CA");
    const cache = new LeafCache(ca);
    const server = tls.createServer(
      {
        SNICallback: (name, cb) =>
          void cache.context(name).then(
            (c) => cb(null, c),
            (e: Error) => cb(e),
          ),
      },
      (s) => s.end("hi"),
    );
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const port = (server.address() as AddressInfo).port;
    const connect = (ca?: string) =>
      new Promise<string>((resolve, reject) => {
        const s = tls.connect({ host: "127.0.0.1", port, servername: "api.stripe.com", ca }, () =>
          s.once("data", (d) => resolve(d.toString())),
        );
        s.once("error", reject);
      });
    await expect(connect(ca.certPem)).resolves.toBe("hi");
    await expect(connect()).rejects.toThrow();
    server.close();
    const leaf = new X509Certificate((await mintLeaf(ca, "api.openai.com")).certPem);
    expect(leaf.subjectAltName).toContain("DNS:api.openai.com");
    expect((Date.parse(leaf.validTo) - Date.now()) / 86_400_000).toBeLessThanOrEqual(30.1);
  });
});
