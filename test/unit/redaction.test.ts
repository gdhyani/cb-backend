import { Readable } from "node:stream";
import { text } from "node:stream/consumers";
import { describe, expect, it } from "vitest";
import { createRedactor, REDACTED, redactHeaders } from "../../src/gateway/http/redaction.js";

describe("redaction (FR-GW-006, S8)", () => {
  it("N3 redacts every secret in header values, including arrays", () => {
    const out = redactHeaders(
      { "x-echo-auth": "Bearer REAL_KEY_123456", "set-cookie": ["a=REAL_KEY_123456", "b=1"], "x-ok": "fine" },
      ["REAL_KEY_123456"],
    );
    expect(out).toEqual({
      "x-echo-auth": `Bearer ${REDACTED}`,
      "set-cookie": [`a=${REDACTED}`, "b=1"],
      "x-ok": "fine",
    });
  });

  it("N3 redacts the base64 form in headers too", () => {
    const b64 = Buffer.from("REAL_KEY_123456").toString("base64");
    expect(redactHeaders({ authorization: `Basic ${b64}` }, ["REAL_KEY_123456"])).toEqual({
      authorization: `Basic ${REDACTED}`,
    });
  });

  it("N3 leaves headers alone when a secret is too short to redact safely", () => {
    expect(redactHeaders({ "x-a": "abc" }, ["abc"])).toEqual({ "x-a": "abc" });
  });

  it("N8 body redactor takes several needles (AWS key id + secret)", async () => {
    const body = "<AWSAccessKeyId>AKIAREALKEY1</AWSAccessKeyId><x>SECRETxyz123</x>";
    const out = await text(
      Readable.from([Buffer.from(body)]).pipe(createRedactor(["AKIAREALKEY1", "SECRETxyz123"])),
    );
    expect(out).not.toContain("AKIAREALKEY1");
    expect(out).not.toContain("SECRETxyz123");
  });

  it("FR-GW-006 a secret split across chunks is still redacted", async () => {
    const out = await text(
      Readable.from([Buffer.from("aa REAL_KEY_"), Buffer.from("123456 bb")]).pipe(
        createRedactor("REAL_KEY_123456"),
      ),
    );
    expect(out).toBe(`aa ${REDACTED} bb`);
  });
});

describe("redaction covers every encoding a secret travels in (I1)", () => {
  const SECRET = "wJalr/XUtnF+EMI=K7MDENG/bPxRfi"; // AWS-like: has / + =
  it("I1 URL-encoded (Location, query), base64url and JSON-escaped forms are redacted", () => {
    const enc = encodeURIComponent(SECRET);
    const out = redactHeaders(
      {
        location: `https://x.test/cb?k=${enc}`,
        "x-b64url": Buffer.from(SECRET).toString("base64url"),
        "x-json": JSON.stringify({ k: SECRET }).replace(/\//g, "\\/"),
      },
      [SECRET],
    );
    expect(JSON.stringify(out)).not.toContain(enc);
    expect(JSON.stringify(out)).not.toContain(Buffer.from(SECRET).toString("base64url"));
    expect(out["x-json"]).not.toContain(SECRET.replace(/\//g, "\\/"));
  });

  it("I1 a body with the JSON-escaped secret is redacted", async () => {
    const body = JSON.stringify({ echo: SECRET }).replace(/\//g, "\\/");
    const out = await text(Readable.from([Buffer.from(body)]).pipe(createRedactor(SECRET)));
    expect(out).not.toContain(SECRET.replace(/\//g, "\\/"));
  });
});
