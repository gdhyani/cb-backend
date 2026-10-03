import { describe, expect, it } from "vitest";
import { EnvError, loadEnv } from "../../src/config/env.js";

const KEY = Buffer.alloc(32, 1).toString("base64");
const base = { MONGODB_URI: "mongodb://127.0.0.1:27017/cb", MASTER_KEY: KEY, SERVER_SECRET: KEY };

describe("loadEnv", () => {
  it("applies defaults", () => {
    expect(loadEnv(base)).toEqual({
      ...base,
      NODE_ENV: "development",
      PORT: 4200,
      LOG_LEVEL: "info",
      DASHBOARD_URL: "http://localhost:4201",
      COOKIE_SECURE: false,
    });
  });

  it("reports every invalid or missing variable at once", () => {
    try {
      loadEnv({ PORT: "abc", NODE_ENV: "staging", MASTER_KEY: "short" });
      expect.unreachable();
    } catch (err) {
      expect(err).toBeInstanceOf(EnvError);
      const keys = (err as EnvError).issues.map((i) => i.key).sort();
      expect(keys).toEqual(["MASTER_KEY", "MONGODB_URI", "NODE_ENV", "PORT", "SERVER_SECRET"]);
      expect((err as EnvError).issues.find((i) => i.key === "SERVER_SECRET")?.message).toBe("is required");
    }
  });

  it("S11 refuses the test-only upstream CA in production", () => {
    expect(() => loadEnv({ ...base, NODE_ENV: "production", UPSTREAM_EXTRA_CA_FILE: "/ca.pem" })).toThrow(
      /test-only/,
    );
  });
});
