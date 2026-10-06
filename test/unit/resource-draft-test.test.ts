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

describe("draft test hits an authenticated path (Save & test must reject bad keys)", () => {
  it("uses the preset's testPath: a provider that 404s on / still rejects a bad key on /v1/balance", async () => {
    const http = await import("node:http");
    const srv = http.createServer((req, res) => {
      if (req.url === "/v1/balance")
        res.writeHead(req.headers.authorization === "Bearer good" ? 200 : 401).end();
      else res.writeHead(404).end();
    });
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    const upstreamUrl = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
    const config = { upstreamUrl, authScheme: "bearer", basePath: "", testPath: "/v1/balance" };
    expect((await runDraftTest("http", "bad", config)).ok).toBe(false);
    expect((await runDraftTest("http", "good", config)).ok).toBe(true);
    srv.close();
  });
});

describe("Save & test for Basic-auth and 400-on-bad-key APIs (review I1, M2)", () => {
  it("I1 Basic auth: the stored key ID is the username, so a valid Razorpay-style secret passes", async () => {
    const http = await import("node:http");
    const want = `Basic ${Buffer.from("rzp_live_ID:secret").toString("base64")}`;
    const srv = http.createServer((req, res) =>
      res.writeHead(req.headers.authorization === want ? 200 : 401).end(),
    );
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    const upstreamUrl = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
    const config = {
      upstreamUrl,
      authScheme: "basic-password",
      basicUser: "rzp_live_ID",
      testPath: "/v1/payments",
    };
    expect((await runDraftTest("http", "secret", config)).ok).toBe(true);
    expect((await runDraftTest("http", "wrong", config)).ok).toBe(false);
    srv.close();
  });

  it("M2 with a testPath, HTTP 400 (Gemini's API_KEY_INVALID) counts as a rejected key", async () => {
    const http = await import("node:http");
    const srv = http.createServer((req, res) =>
      res.writeHead(req.headers["x-goog-api-key"] === "good" ? 200 : 400).end(),
    );
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    const upstreamUrl = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
    const config = {
      upstreamUrl,
      authScheme: "header",
      authHeader: "x-goog-api-key",
      testPath: "/v1beta/models",
    };
    expect((await runDraftTest("http", "bad", config)).ok).toBe(false);
    expect((await runDraftTest("http", "good", config)).ok).toBe(true);
    srv.close();
  });
});

describe("AWS Save & test: a scoped key that may not list buckets is still a valid key", () => {
  const s3 = async (answer: (auth: string) => { status: number; code?: string }) => {
    const http = await import("node:http");
    const srv = http.createServer((req, res) => {
      const a = answer(String(req.headers.authorization ?? ""));
      res.writeHead(a.status, { "content-type": "application/xml" });
      res.end(a.code ? `<Error><Code>${a.code}</Code></Error>` : "<ListAllMyBucketsResult/>");
    });
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    return { endpoint: `http://127.0.0.1:${(srv.address() as AddressInfo).port}`, close: () => srv.close() };
  };
  const secret = JSON.stringify({ accessKeyId: "AKIAEXAMPLE000000000", secretAccessKey: "x".repeat(40) });

  it("AccessDenied (signature checked, action not allowed) passes with a clear note", async () => {
    const srv = await s3(() => ({ status: 403, code: "AccessDenied" }));
    const r = await runDraftTest("aws", secret, { region: "ap-southeast-1", endpoint: srv.endpoint });
    expect(r.ok).toBe(true);
    expect(r.message).toMatch(/key accepted.*can't list buckets/i);
    srv.close();
  });

  it("a wrong key or secret still fails (InvalidAccessKeyId, SignatureDoesNotMatch)", async () => {
    for (const code of ["InvalidAccessKeyId", "SignatureDoesNotMatch"]) {
      const srv = await s3(() => ({ status: 403, code }));
      const r = await runDraftTest("aws", secret, { region: "ap-southeast-1", endpoint: srv.endpoint });
      expect(r.ok, code).toBe(false);
      expect(r.message).toContain(code);
      srv.close();
    }
  });
});
