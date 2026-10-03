import { spawnSync } from "node:child_process";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { startup } from "../../src/lifecycle.js";
import { startMemoryMongo } from "../helpers/mongo.js";

let mongo: Awaited<ReturnType<typeof startMemoryMongo>>;
beforeAll(async () => {
  mongo = await startMemoryMongo();
});
afterAll(async () => mongo.stop());

describe("lifecycle", () => {
  it("refuses to start with invalid env and lists every problem", () => {
    const r = spawnSync(process.execPath, ["--import", "tsx", path.resolve("src/index.ts")], {
      env: { PATH: process.env.PATH, PORT: "abc", NODE_ENV: "development" },
      encoding: "utf8",
      timeout: 20_000,
    });
    expect(r.status).toBe(1);
    const out = r.stdout + r.stderr;
    expect(out).toContain("MONGODB_URI");
    expect(out).toContain("PORT");
  });

  it("starts, serves health, then shuts down cleanly", async () => {
    const running = await startup({
      env: { NODE_ENV: "test", PORT: "0", MONGODB_URI: mongo.uri },
      exitOnShutdown: false,
      installSignalHandlers: false,
    });
    const res = await fetch(`http://127.0.0.1:${running.port}/api/health`);
    expect(res.status).toBe(200);
    await running.shutdown("test");
    await expect(fetch(`http://127.0.0.1:${running.port}/api/health`)).rejects.toThrow();
  });
});
