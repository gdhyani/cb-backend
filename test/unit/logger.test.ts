import { describe, expect, it } from "vitest";
import { redact } from "../../src/logger/logger.js";

describe("redact", () => {
  it("replaces sensitive values recursively", () => {
    const out = redact({
      headers: { authorization: "Bearer abc", cookie: "sid=1", accept: "json" },
      body: { password: "hunter2", apiToken: "t", clientSecret: "s", name: "ok" },
    });
    expect(out).toEqual({
      headers: { authorization: "[redacted]", cookie: "[redacted]", accept: "json" },
      body: { password: "[redacted]", apiToken: "[redacted]", clientSecret: "[redacted]", name: "ok" },
    });
  });
});
