import { randomBytes } from "node:crypto";
import fs from "node:fs";
import https from "node:https";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import zlib from "node:zlib";
import { createCa, mintLeaf } from "../../src/crypto/ca.js";

const rand = () =>
  randomBytes(16)
    .toString("base64")
    .replace(/[^A-Za-z0-9]/g, "")
    .slice(0, 14);

/**
 * HTTPS stand-in for Stripe and Razorpay object creation (private CA). Accepts only the real keys and answers with
 * fresh object ids, like the real APIs — enough for the gateway to learn which device created what.
 */
export async function startMockPayments(opts: {
  stripeKey: string;
  razorpayKeyId: string;
  razorpaySecret: string;
}) {
  const ca = await createCa("cb test payments CA");
  const leaf = await mintLeaf(ca, "localhost");
  const caFile = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "cb-pay-ca-")), "ca.pem");
  fs.writeFileSync(caFile, ca.certPem);
  const basic = `Basic ${Buffer.from(`${opts.razorpayKeyId}:${opts.razorpaySecret}`).toString("base64")}`;
  const server = https.createServer({ cert: leaf.certPem, key: leaf.keyPem }, (req, res) => {
    req.resume();
    // Like the real APIs: compressed when the client accepts it (the gateway must still learn the ids).
    const gzip = /\bgzip\b/.test(String(req.headers["accept-encoding"] ?? ""));
    const send = (status: number, body: unknown) => {
      const text = Buffer.from(JSON.stringify(body));
      res.writeHead(status, {
        "content-type": "application/json",
        ...(gzip ? { "content-encoding": "gzip" } : {}),
      });
      res.end(gzip ? zlib.gzipSync(text) : text);
    };
    const url = req.url ?? "";
    if (url.startsWith("/v1/payment_intents")) {
      if (req.headers.authorization !== `Bearer ${opts.stripeKey}`)
        return send(401, { error: { type: "auth" } });
      const confirm = /^\/v1\/payment_intents\/(pi_[A-Za-z0-9]+)\/confirm/.exec(url);
      if (confirm) return send(200, { id: confirm[1], status: "succeeded", latest_charge: `ch_${rand()}` });
      const id = `pi_${rand()}`;
      return send(200, {
        id,
        object: "payment_intent",
        client_secret: `${id}_secret_${rand()}`,
        customer: null,
      });
    }
    if (url.startsWith("/v1/orders")) {
      if (req.headers.authorization !== basic) return send(401, { error: { code: "BAD_REQUEST_ERROR" } });
      return send(200, { id: `order_${rand()}`, entity: "order", status: "created" });
    }
    send(404, { error: "not found" });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return {
    url: `https://localhost:${(server.address() as AddressInfo).port}`,
    caFile,
    close: () => server.close(),
  };
}
