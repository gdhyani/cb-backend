import { describe, expect, it } from "vitest";
import { isPrivateHost, UpstreamUrl } from "../../src/utils/upstream-url.js";

describe("D11 upstream URL rule (FR-GW-004)", () => {
  it("treats loopback, RFC 1918, ULA and localhost as private", () => {
    for (const h of [
      "127.0.0.1",
      "10.0.4.12",
      "172.16.0.1",
      "172.31.255.255",
      "192.168.1.9",
      "localhost",
      "[::1]",
      "::1",
      "[fd12::1]",
    ])
      expect(isPrivateHost(h), h).toBe(true);
    for (const h of ["8.8.8.8", "172.32.0.1", "11.0.0.1", "api.openai.com", "llm.internal", "[2001:db8::1]"])
      expect(isPrivateHost(h), h).toBe(false);
  });

  it("accepts https anywhere and http only for private hosts", () => {
    expect(UpstreamUrl.safeParse("https://api.example.com").success).toBe(true);
    expect(UpstreamUrl.safeParse("http://10.0.4.12:8000/v1").success).toBe(true);
    expect(UpstreamUrl.safeParse("http://localhost:11434").success).toBe(true);
    expect(UpstreamUrl.safeParse("http://api.example.com").success).toBe(false);
    expect(UpstreamUrl.safeParse("http://llm.internal:8000").success).toBe(false);
    expect(UpstreamUrl.safeParse("ftp://10.0.0.1").success).toBe(false);
  });
});

describe("OQ11 plain http to private addresses can be switched off (hosted deployments)", () => {
  it("ALLOW_PRIVATE_HTTP_UPSTREAMS=false refuses http:// even to private addresses; https stays fine", async () => {
    const { loadEnv, setEnv } = await import("../../src/config/env.js");
    const { testEnvVars } = await import("../helpers/env.js");
    setEnv(loadEnv({ ...testEnvVars("mongodb://127.0.0.1:1/x"), ALLOW_PRIVATE_HTTP_UPSTREAMS: "false" }));
    try {
      expect(UpstreamUrl.safeParse("http://10.0.0.5:8080").success).toBe(false);
      expect(UpstreamUrl.safeParse("http://localhost:11434").success).toBe(false);
      expect(UpstreamUrl.safeParse("https://api.example.com").success).toBe(true);
    } finally {
      setEnv(loadEnv(testEnvVars("mongodb://127.0.0.1:1/x")));
    }
    expect(UpstreamUrl.safeParse("http://10.0.0.5:8080").success).toBe(true); // default: on (local dev)
  });
});
