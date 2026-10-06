import { describe, expect, it } from "vitest";
import { PRIVATE_CA_HINT, privateCaHint } from "../../src/services/resource-test.service.js";

const certError = (code: string) =>
  Object.assign(new Error("self-signed certificate in certificate chain"), { code });

describe("private-CA hint for databases (Aiven, FR-GW-004)", () => {
  it.each([
    "SELF_SIGNED_CERT_IN_CHAIN",
    "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
    "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
    "DEPTH_ZERO_SELF_SIGNED_CERT",
  ])("a %s failure on a database without a CA suggests adding the CA", (code) => {
    expect(privateCaHint("mysql", {}, certError(code))).toBe(PRIVATE_CA_HINT);
    expect(privateCaHint("postgres", {}, certError(code))).toBe(PRIVATE_CA_HINT);
  });

  it("no hint once a CA is set, for other kinds, or for other errors", () => {
    expect(
      privateCaHint(
        "mysql",
        { caCert: "-----BEGIN CERTIFICATE-----" },
        certError("SELF_SIGNED_CERT_IN_CHAIN"),
      ),
    ).toBeUndefined();
    expect(privateCaHint("http", {}, certError("SELF_SIGNED_CERT_IN_CHAIN"))).toBeUndefined();
    expect(
      privateCaHint("mysql", {}, Object.assign(new Error("refused"), { code: "ECONNREFUSED" })),
    ).toBeUndefined();
  });

  it("the hint is found on a wrapped cause too (drivers wrap TLS errors)", () => {
    const wrapped = Object.assign(new Error("connect failed"), {
      cause: certError("SELF_SIGNED_CERT_IN_CHAIN"),
    });
    expect(privateCaHint("mysql", {}, wrapped)).toBe(PRIVATE_CA_HINT);
  });
});
