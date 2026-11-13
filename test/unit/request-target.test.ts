import net from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { loadEnv, setEnv } from "../../src/config/env.js";
import { createHttpHandler } from "../../src/gateway/http/http-adapter.js";
import { originFormTarget } from "../../src/gateway/http/upstream.js";
import type { TunnelContext } from "../../src/gateway/types.js";
import { fakeApiKey } from "../../src/services/fakes.service.js";
import { testEnvVars } from "../helpers/env.js";

/**
 * S1 / FR-GW-005 (M7 security review, Critical): the app's request target must never choose the upstream host.
 * An absolute-form (`http://evil/x`) or scheme-relative (`//evil/x`) path used to make `new URL(path, origin)` point
 * at another host, and the gateway sent the REAL key there.
 */
describe("S1 request targets stay on the configured upstream", () => {
  const upstream = new URL("https://api.example.test/v1");

  it("S1 builds origin-form targets under the configured origin and prefix", () => {
    expect(originFormTarget(upstream, "/chat?x=1")?.href).toBe("https://api.example.test/v1/chat?x=1");
    expect(originFormTarget(new URL("https://api.example.test"), "/")?.href).toBe(
      "https://api.example.test/",
    );
  });

  it.each([
    "http://attacker.example/x",
    "https://attacker.example/x",
    "//attacker.example/x",
    "/\\attacker.example/x",
    "\\\\attacker.example/x",
    "attacker.example/x",
    "",
    "*",
  ])("S1 refuses a non-origin-form target %j", (path) => {
    expect(originFormTarget(upstream, path)).toBeNull();
  });

  describe("S1 the HTTP adapter never sends the real key to a host named in the path", () => {
    let attacker: net.Server;
    let attackerPort = 0;
    let connections = 0;
    beforeAll(async () => {
      setEnv(loadEnv(testEnvVars("mongodb://127.0.0.1:1/x")));
      attacker = net.createServer((s) => {
        connections += 1;
        s.destroy();
      });
      await new Promise<void>((r) => attacker.listen(0, "127.0.0.1", r));
      attackerPort = (attacker.address() as net.AddressInfo).port;
    });
    afterAll(() => new Promise<void>((r) => attacker.close(() => r())));

    const scope = { deviceId: "d1", environmentId: "e1", resourceId: "r1" };
    const ctx = {
      ...scope,
      id: "t1",
      userId: "u1",
      orgId: "o1",
      projectId: "p1",
      layer: "1",
      secret: "REAL_KEY_123456",
      resource: {
        id: "r1",
        kind: "http",
        name: "llm",
        config: { upstreamUrl: "https://api.example.test", fakePrefix: "cb_" },
      },
    } as unknown as TunnelContext;

    function send(url: string): Promise<{ status: number; body: string }> {
      return new Promise((resolve) => {
        const res = {
          headersSent: false,
          writeHead(status: number) {
            this.status = status;
          },
          status: 0,
          end(body: string) {
            resolve({ status: this.status, body });
          },
        };
        const req = {
          headers: { authorization: `Bearer ${fakeApiKey(scope, "cb_")}` },
          url,
          method: "GET",
          resume() {},
        };
        createHttpHandler(ctx)(req as never, res as never);
      });
    }

    it.each(["http", "scheme-relative"])(
      "S1 %s request target is refused before any connection",
      async (form) => {
        const url =
          form === "http" ? `http://127.0.0.1:${attackerPort}/steal` : `//127.0.0.1:${attackerPort}/steal`;
        const before = connections;
        const r = await send(url);
        await new Promise((t) => setTimeout(t, 200));
        expect(connections).toBe(before);
        expect(r.status).toBe(400);
        expect(JSON.parse(r.body)).toEqual({ error: "cb_bad_request_target" });
      },
    );
  });
});
