import { describe, expect, it } from "vitest";
import { EnvError, loadEnv } from "../../src/config/env.js";

describe("loadEnv", () => {
  it("applies defaults", () => {
    const env = loadEnv({ MONGODB_URI: "mongodb://127.0.0.1:27017/cb" });
    expect(env).toEqual({
      NODE_ENV: "development",
      PORT: 4200,
      LOG_LEVEL: "info",
      MONGODB_URI: "mongodb://127.0.0.1:27017/cb",
    });
  });

  it("reports every invalid or missing variable at once", () => {
    try {
      loadEnv({ PORT: "abc", NODE_ENV: "staging" });
      expect.unreachable();
    } catch (err) {
      expect(err).toBeInstanceOf(EnvError);
      const issues = (err as EnvError).issues.map((i) => i.key).sort();
      expect(issues).toEqual(["MONGODB_URI", "NODE_ENV", "PORT"]);
      expect((err as EnvError).message).toContain("MONGODB_URI");
      expect((err as EnvError).message).toContain("PORT");
    }
  });
});
