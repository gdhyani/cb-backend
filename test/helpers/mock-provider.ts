import fs from "node:fs";
import https from "node:https";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import { createCa, mintLeaf } from "../../src/crypto/ca.js";

export interface ProviderRequest {
  path: string;
  authorization?: string;
}

/** HTTPS "provider" on a private CA that only accepts the real key. Echoes the secret back to test redaction. */
export async function startMockProvider(realKey: string, clientSecret = "unused-client-secret") {
  const ca = await createCa("cb test provider CA");
  const leaf = await mintLeaf(ca, "localhost");
  const caFile = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "cb-ca-")), "ca.pem");
  fs.writeFileSync(caFile, ca.certPem);
  const requests: ProviderRequest[] = [];
  const server = https.createServer({ cert: leaf.certPem, key: leaf.keyPem }, (req, res) => {
    requests.push({ path: req.url ?? "", authorization: req.headers.authorization });
    if (req.method === "POST" && req.url === "/token") {
      let body = "";
      req.on("data", (c) => {
        body += c;
      });
      req.on("end", () => {
        const ok = new URLSearchParams(body).get("client_secret") === clientSecret;
        res.writeHead(ok ? 200 : 401, { "content-type": "application/json" });
        res.end(
          JSON.stringify(
            ok ? { access_token: "at_1", echo: `secret was ${clientSecret}` } : { error: "invalid_client" },
          ),
        );
      });
      return;
    }
    const ok = req.headers.authorization === `Bearer ${realKey}`;
    res.writeHead(ok ? 200 : 401, { "content-type": "application/json" });
    res.end(JSON.stringify(ok ? { ok: true, path: req.url, echo: `token was ${realKey}` } : { ok: false }));
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address() as AddressInfo;
  return { url: `https://localhost:${port}`, caFile, requests, close: () => server.close() };
}
