import { describe, expect, it } from "vitest";
import { AppError } from "../../src/errors/app-error.js";
import { parseMongoUri, parsePostgresUri } from "../../src/utils/connection-uri.js";

const detailOf = (fn: () => unknown) => {
  try {
    fn();
  } catch (err) {
    if (err instanceof AppError) return err.details?.[0]?.message;
    throw err;
  }
  throw new Error("expected a validation error");
};

describe("connection URI parsing (J2 resource forms)", () => {
  it("names an out-of-range port instead of a generic error", () => {
    expect(detailOf(() => parseMongoUri("mongodb://localhost:72172/main-db"))).toBe(
      "port 72172 is out of range (1–65535)",
    );
    expect(detailOf(() => parsePostgresUri("postgresql://u:p@db:0/x"))).toBe(
      "port 0 is out of range (1–65535)",
    );
  });

  it("asks for a scheme when it is missing", () => {
    expect(detailOf(() => parseMongoUri("localhost:27017/main-db"))).toBe(
      "must start with a scheme, e.g. mongodb://",
    );
  });

  it("parses valid URIs with credentials and defaults the port", () => {
    const parsed = parseMongoUri("mongodb://shop:s3cret@localhost:27018/main-db?authSource=admin");
    expect(parsed).toMatchObject({ host: "localhost", port: 27018, database: "main-db", username: "shop" });
    expect(parsePostgresUri("postgresql://u:p@db.internal/orders").port).toBe(5432);
  });
});
