import { Types } from "mongoose";
import { describe, expect, it } from "vitest";
import { createCa } from "../../src/crypto/ca.js";
import { toResourceDto } from "../../src/services/resource.service.js";
import { pemBodyLines } from "../helpers/sweep.js";

const row = (config: Record<string, unknown>) => ({
  _id: new Types.ObjectId(),
  environmentId: new Types.ObjectId(),
  kind: "mysql",
  name: "db",
  config,
});

describe("resource DTO never returns a CA PEM (M6, L15)", () => {
  it("M6 a row from before the file-store migration shows the inline CA as subject and expiry only", async () => {
    const ca = await createCa("Legacy Inline CA");
    const dto = toResourceDto(row({ host: "db.example.com", caCert: ca.certPem }));
    const body = JSON.stringify(dto);
    expect(body).not.toContain("BEGIN CERTIFICATE");
    for (const line of pemBodyLines(ca.certPem)) expect(body).not.toContain(line);
    expect(dto.config).not.toHaveProperty("caCert");
    expect(dto.config.caCertFile).toEqual({
      subject: expect.stringContaining("Legacy Inline CA"),
      notAfter: expect.stringMatching(/^\d{4}-\d\d-\d\dT/),
      size: Buffer.byteLength(ca.certPem),
    });
    expect(dto.config.host).toBe("db.example.com");
  });

  it("M6 an unreadable inline value is dropped rather than echoed", () => {
    const dto = toResourceDto(
      row({ caCert: "-----BEGIN CERTIFICATE-----\nnot-a-cert\n-----END CERTIFICATE-----" }),
    );
    expect(JSON.stringify(dto)).not.toContain("not-a-cert");
    expect(dto.config).not.toHaveProperty("caCert");
  });
});
