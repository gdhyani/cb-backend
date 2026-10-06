import { describe, expect, it } from "vitest";
import { healthFromHttp, healthFromUpstreamError } from "../../src/services/resource-health.service.js";

describe("key health classification (B11)", () => {
  it("an HTTP API answering 401 means the provider rejected the key", () => {
    expect(healthFromHttp("http", 401, "")).toMatchObject({
      status: "rejected",
      reason: expect.stringMatching(/401/),
    });
    expect(healthFromHttp("oauth", 401, '{"error":"invalid_client"}')?.status).toBe("rejected");
  });

  it("2xx means working; other errors say nothing about the key", () => {
    expect(healthFromHttp("http", 200, "")?.status).toBe("ok");
    expect(healthFromHttp("http", 404, "")).toBeUndefined();
    expect(healthFromHttp("http", 429, "")).toBeUndefined();
    expect(healthFromHttp("http", 500, "")).toBeUndefined();
  });

  it("AWS: a 403 is a rejected key only for an unknown key id or a bad signature, not for AccessDenied", () => {
    expect(healthFromHttp("aws", 403, "<Code>InvalidAccessKeyId</Code>")?.status).toBe("rejected");
    expect(healthFromHttp("aws", 403, "<Code>SignatureDoesNotMatch</Code>")?.status).toBe("rejected");
    expect(healthFromHttp("aws", 403, '{"__type":"UnrecognizedClientException"}')?.status).toBe("rejected");
    expect(healthFromHttp("aws", 403, "<Code>AccessDenied</Code>")).toBeUndefined();
  });

  it("Gemini: an invalid key comes back as 400 API_KEY_INVALID", () => {
    expect(
      healthFromHttp(
        "http",
        400,
        '{"error":{"status":"INVALID_ARGUMENT","details":[{"reason":"API_KEY_INVALID"}]}}',
      )?.status,
    ).toBe("rejected");
    expect(healthFromHttp("http", 400, '{"error":"bad request"}')).toBeUndefined();
  });

  it("databases: an upstream login failure is a rejected key; other failures are not", () => {
    for (const m of [
      "postgres rejected the stored credentials (password authentication failed)",
      "mysql rejected the stored credentials (Access denied for user)",
      "redis rejected the stored credentials",
      "mongodb authentication failed (AuthenticationFailed)",
      'smtp upstream rejected "AUTH" (535 Authentication failed)',
    ])
      expect(healthFromUpstreamError(m)?.status, m).toBe("rejected");
    expect(healthFromUpstreamError("postgres unreachable (ECONNREFUSED)")).toBeUndefined();
  });

  it("a reason is cb's own words: it never repeats the provider's body", () => {
    const h = healthFromHttp("http", 401, '{"error":"Invalid API key sk_live_1234…abcd"}');
    expect(h?.reason).not.toContain("sk_live");
    const d = healthFromUpstreamError(
      "mysql rejected the stored credentials (Access denied for user 'admin'@'1.2.3.4')",
    );
    expect(d?.reason).not.toContain("admin");
  });
});
