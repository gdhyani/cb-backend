import fs from "node:fs";
import http2 from "node:http2";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import { createCa, mintLeaf } from "../../src/crypto/ca.js";
import { verifyJwt } from "../../src/crypto/jwt.js";

export interface MockPushOptions {
  google: { clientEmail: string; publicPem: string; accessToken: string; oauthClientSecret?: string };
  apns: { keyId: string; teamId: string; publicPem: string };
}

/**
 * Stand-in for oauth2.googleapis.com + fcm.googleapis.com + api.push.apple.com on a private CA (HTTP/2 and 1.1).
 * Accepts only assertions/JWTs signed with the REAL keys and only the real Google access token.
 */
export async function startMockPush(opts: MockPushOptions) {
  const ca = await createCa("cb test push CA");
  const leaf = await mintLeaf(ca, "localhost");
  const caFile = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "cb-push-ca-")), "ca.pem");
  fs.writeFileSync(caFile, ca.certPem);
  const seen: { path: string; authorization?: string; body: string }[] = [];

  const server = http2.createSecureServer(
    { cert: leaf.certPem, key: leaf.keyPem, allowHTTP1: true },
    (req, res) => {
      let body = "";
      req.on("data", (c: Buffer) => {
        body += c.toString();
      });
      req.on("end", () => {
        const url = req.url ?? "/";
        const authorization = req.headers.authorization;
        seen.push({ path: url, authorization, body });
        const json = (status: number, value: unknown, headers: Record<string, string> = {}) => {
          res.writeHead(status, { "content-type": "application/json", ...headers });
          res.end(JSON.stringify(value));
        };
        if (url === "/token") {
          const form = new URLSearchParams(body);
          // OAuth client flow (Google sign-in): only the real client secret is accepted.
          if (form.has("client_secret")) {
            const ok =
              opts.google.oauthClientSecret && form.get("client_secret") === opts.google.oauthClientSecret;
            return ok
              ? json(200, {
                  access_token: "user-access-token",
                  token_type: "Bearer",
                  echo: `secret was ${form.get("client_secret")}`,
                })
              : json(401, { error: "invalid_client" });
          }
          const assertion = form.get("assertion") ?? "";
          const jwt = verifyJwt(assertion, "RS256", opts.google.publicPem);
          if (!jwt || jwt.payload.iss !== opts.google.clientEmail)
            return json(400, { error: "invalid_grant" });
          return json(200, { access_token: opts.google.accessToken, expires_in: 3599, token_type: "Bearer" });
        }
        if (url.startsWith("/v1/projects/")) {
          if (authorization !== `Bearer ${opts.google.accessToken}`)
            return json(401, { error: { status: "UNAUTHENTICATED" } });
          // Echo the token to prove the gateway redacts it.
          return json(200, {
            name: `${url.slice(4).replace(/\/messages:send$/, "")}/messages/1`,
            echo: authorization,
          });
        }
        if (url.startsWith("/3/device/")) {
          const token = /^bearer\s+(\S+)$/i.exec(authorization ?? "")?.[1] ?? "";
          const jwt = verifyJwt(token, "ES256", opts.apns.publicPem);
          if (!jwt || jwt.header.kid !== opts.apns.keyId || jwt.payload.iss !== opts.apns.teamId)
            return json(403, { reason: "InvalidProviderToken" });
          res.writeHead(200, { "apns-id": "11111111-2222-3333-4444-555555555555" });
          return res.end();
        }
        json(404, { error: "not found" });
      });
    },
  );
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address() as AddressInfo;
  return { url: `https://localhost:${port}`, caFile, seen, close: () => server.close() };
}
