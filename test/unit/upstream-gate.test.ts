import { describe, expect, it } from "vitest";
import { loadEnv, setEnv } from "../../src/config/env.js";
import { createHttpHandler } from "../../src/gateway/http/http-adapter.js";
import type { TunnelContext } from "../../src/gateway/types.js";
import { fakeApiKey } from "../../src/services/fakes.service.js";
import { testEnvVars } from "../helpers/env.js";

describe("OQ11 the gateway re-checks plain-http upstreams when connecting (services saved before the switch)", () => {
  it("refuses a stored http:// private upstream once ALLOW_PRIVATE_HTTP_UPSTREAMS=false", () => {
    setEnv(loadEnv({ ...testEnvVars("mongodb://127.0.0.1:1/x"), ALLOW_PRIVATE_HTTP_UPSTREAMS: "false" }));
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
        config: { upstreamUrl: "http://10.0.0.5:11434", fakePrefix: "cb_" },
      },
    } as unknown as TunnelContext;
    let status = 0;
    let body = "";
    const res = {
      headersSent: false,
      writeHead: (s: number) => {
        status = s;
      },
      end: (t: string) => {
        body = t;
      },
    };
    const req = {
      headers: { authorization: `Bearer ${fakeApiKey(scope, "cb_")}` },
      url: "/v1/models",
      method: "GET",
      resume() {},
    };
    createHttpHandler(ctx)(req as never, res as never);
    expect(status).toBe(403);
    expect(JSON.parse(body)).toEqual({ error: "cb_upstream_not_allowed" });
    setEnv(loadEnv(testEnvVars("mongodb://127.0.0.1:1/x")));
  });
});
