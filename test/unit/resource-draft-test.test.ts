import type { AddressInfo } from "node:net";
import net from "node:net";
import { beforeAll, describe, expect, it } from "vitest";
import { loadEnv, setEnv } from "../../src/config/env.js";
import { runDraftTest } from "../../src/services/resource-test.service.js";
import { testEnvVars } from "../helpers/env.js";

beforeAll(() => setEnv(loadEnv(testEnvVars("mongodb://127.0.0.1:1/x"))));

describe("draft connection test (J2)", () => {
  it("reports a refused connection without the secret in the message", async () => {
    const srv = net.createServer((s) => s.destroy());
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    const port = (srv.address() as AddressInfo).port;
    srv.close();
    const secret = `redis://default:TOPSECRET_PW_1@127.0.0.1:${port}`;
    const r = await runDraftTest("redis", secret, { tls: false });
    expect(r.ok).toBe(false);
    expect(r.message).not.toContain("TOPSECRET_PW_1");
    expect(r.latencyMs).toBeGreaterThanOrEqual(0);
  });
});
