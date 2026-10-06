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

describe("AWS Save & test checks each service with a call of its own kind (SES, SQS)", () => {
  const aws = async (
    handler: (
      req: import("node:http").IncomingMessage,
      body: string,
    ) => { status: number; body: string; errorType?: string },
  ) => {
    const http = await import("node:http");
    const seen: { method: string; url: string; target?: string; scope?: string }[] = [];
    const srv = http.createServer((req, res) => {
      let body = "";
      req.on("data", (c) => {
        body += c;
      });
      req.on("end", () => {
        const scope = /Credential=[^/]+\/\d+\/([^/]+)\/([^/]+)\//.exec(
          String(req.headers.authorization ?? ""),
        );
        seen.push({
          method: req.method ?? "",
          url: req.url ?? "",
          target: req.headers["x-amz-target"] as string,
          scope: scope ? `${scope[1]}/${scope[2]}` : undefined,
        });
        const a = handler(req, body);
        res.writeHead(a.status, {
          "content-type": "application/json",
          ...(a.errorType ? { "x-amzn-errortype": a.errorType } : {}),
        });
        res.end(a.body);
      });
    });
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    return { port: (srv.address() as AddressInfo).port, seen, close: () => srv.close() };
  };
  const secret = JSON.stringify({ accessKeyId: "AKIAEXAMPLE000000000", secretAccessKey: "x".repeat(40) });

  it("SES: signs GetAccount for ses in the region; AccessDenied is a valid key, a bad token is not", async () => {
    let answer: { status: number; body: string; errorType?: string } = { status: 200, body: "{}" };
    const srv = await aws(() => answer);
    // The service is read from the endpoint: email.<region>.amazonaws.com, here via awsService for the local stand-in.
    const config = { region: "ap-southeast-1", endpoint: `http://127.0.0.1:${srv.port}`, awsService: "ses" };
    expect((await runDraftTest("aws", secret, config)).ok).toBe(true);
    expect(srv.seen.at(-1)).toMatchObject({
      method: "GET",
      url: "/v2/email/account",
      scope: "ap-southeast-1/ses",
    });
    answer = {
      status: 403,
      body: JSON.stringify({ __type: "AccessDeniedException", message: "not authorized" }),
    };
    const denied = await runDraftTest("aws", secret, config);
    expect(denied.ok).toBe(true);
    expect(denied.message).toMatch(/key accepted/i);
    // SES v2 (REST-JSON) puts the error type in a header and only a Message in the body — like the real API.
    answer = {
      status: 403,
      body: JSON.stringify({ Message: "not authorized to perform: ses:GetAccount" }),
      errorType: "AccessDeniedException:http://internal.amazon.com/coral/",
    };
    expect((await runDraftTest("aws", secret, config)).ok).toBe(true);
    answer = {
      status: 403,
      body: JSON.stringify({ Message: "The security token included in the request is invalid." }),
      errorType: "UnrecognizedClientException",
    };
    expect((await runDraftTest("aws", secret, config)).message).toContain("UnrecognizedClientException");
    answer = {
      status: 403,
      body: JSON.stringify({
        __type: "UnrecognizedClientException",
        message: "The security token included in the request is invalid.",
      }),
    };
    const bad = await runDraftTest("aws", secret, config);
    expect(bad.ok).toBe(false);
    expect(bad.message).toContain("UnrecognizedClientException");
    srv.close();
  });

  it("SQS: signs ListQueues (JSON protocol) for sqs; InvalidClientTokenId fails", async () => {
    let answer = { status: 200, body: JSON.stringify({ QueueUrls: [] }) };
    const srv = await aws(() => answer);
    const config = { region: "eu-west-1", endpoint: `http://127.0.0.1:${srv.port}`, awsService: "sqs" };
    expect((await runDraftTest("aws", secret, config)).ok).toBe(true);
    expect(srv.seen.at(-1)).toMatchObject({
      method: "POST",
      url: "/",
      target: "AmazonSQS.ListQueues",
      scope: "eu-west-1/sqs",
    });
    answer = {
      status: 400,
      body: JSON.stringify({ __type: "com.amazon.coral.service#InvalidClientTokenId", message: "bad" }),
    };
    expect((await runDraftTest("aws", secret, config)).ok).toBe(false);
    srv.close();
  });

  it("the service is read from AWS endpoints: email. → ses, sqs. → sqs, anything else → s3", async () => {
    const { awsServiceOf } = await import("../../src/services/resource-test.service.js");
    expect(awsServiceOf({ endpoint: "https://email.ap-southeast-1.amazonaws.com" })).toBe("ses");
    expect(awsServiceOf({ endpoint: "https://sqs.eu-west-1.amazonaws.com" })).toBe("sqs");
    expect(awsServiceOf({ endpoint: "https://s3.us-east-1.amazonaws.com" })).toBe("s3");
    expect(awsServiceOf({ endpoint: "https://abc.r2.cloudflarestorage.com" })).toBe("s3");
    expect(awsServiceOf({ endpoint: "https://s3.us-east-1.amazonaws.com", awsService: "ses" })).toBe("ses");
  });
});
