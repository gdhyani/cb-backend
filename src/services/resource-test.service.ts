import http2 from "node:http2";
import { Hash } from "@smithy/hash-node";
import { HttpRequest } from "@smithy/protocol-http";
import { SignatureV4 } from "@smithy/signature-v4";
import { Redis } from "ioredis";
import { MongoClient } from "mongodb";
import type { Types } from "mongoose";
import mysql from "mysql2/promise";
import nodemailer from "nodemailer";
import pg from "pg";
import { request } from "undici";
import { signJwt } from "../crypto/jwt.js";
import { AppError } from "../errors/app-error.js";
import { type AuthScheme, injectCredential } from "../gateway/http/http-adapter.js";
import { upstreamCa, upstreamDispatcher } from "../gateway/http/upstream.js";
import { type ResourceKind, ResourceModel } from "../models/resource.model.js";
import { MYSQL_TLS_HINT, mysqlWantsTls, parseMongoUri } from "../utils/connection-uri.js";
import { requireMembership } from "./access.service.js";
import { recordAudit } from "./audit.service.js";
import { DEFAULT_PROFILE, readProfileSecret } from "./profile.service.js";
import { readResourceSecret } from "./resource-secret.service.js";

const TIMEOUT_MS = 8000;

export interface ResourceTestDto {
  ok: boolean;
  profile: string;
  latencyMs: number;
  /** Human-readable outcome; never contains the credential. */
  message: string;
}

type Outcome = { ok: boolean; message: string };

/** Strips the credential (and URL-encoded / password parts of it) from anything we report or log. */
function scrub(text: string, secret: string): string {
  let out = text;
  const parts = [secret, encodeURIComponent(secret)];
  try {
    const url = new URL(secret);
    if (url.password) parts.push(url.password, decodeURIComponent(url.password));
  } catch {
    // Not a URL secret.
  }
  for (const p of parts.filter((x) => x.length >= 4)) out = out.split(p).join("•••");
  return out;
}

const withTimeout = <T>(p: Promise<T>, what: string) =>
  Promise.race([
    p,
    new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error(`${what} timed out after 8 s`)), TIMEOUT_MS),
    ),
  ]);

const tlsWanted = (config: Record<string, unknown>) => config.tls === true;

const testers: Record<ResourceKind, (secret: string, config: Record<string, unknown>) => Promise<Outcome>> = {
  async postgres(secret, config) {
    // pg lets sslmode/sslrootcert in the URI override the ssl option, which would drop our verified CA list.
    const url = new URL(secret);
    for (const k of ["sslmode", "sslrootcert", "sslcert", "sslkey", "ssl"]) url.searchParams.delete(k);
    const client = new pg.Client({
      connectionString: url.toString(),
      connectionTimeoutMillis: TIMEOUT_MS,
      ...(tlsWanted(config) ? { ssl: { ca: upstreamCa(config.caCert), rejectUnauthorized: true } } : {}),
    });
    await client.connect();
    try {
      const { rows } = await client.query("SELECT current_user AS u, version() AS v");
      return {
        ok: true,
        message: `Connected as ${rows[0]?.u} (${String(rows[0]?.v).split(" ").slice(0, 2).join(" ")})`,
      };
    } finally {
      await client.end();
    }
  },
  async mysql(secret, config) {
    // Decide TLS from the URI like the gateway does (older services stored tls:false next to ?ssl=true), and keep
    // ssl/ssl-mode/sslmode out of what mysql2 parses: it rejects ssl=true ("SSL profile must be an object").
    const url = new URL(secret);
    const wantsTls = tlsWanted(config) || mysqlWantsTls(url.searchParams);
    for (const k of ["ssl", "ssl-mode", "sslmode", "tls"]) url.searchParams.delete(k);
    const conn = await mysql
      .createConnection({
        uri: url.toString(),
        connectTimeout: TIMEOUT_MS,
        ...(wantsTls ? { ssl: { ca: upstreamCa(config.caCert), rejectUnauthorized: true } } : {}),
      })
      .catch((err: { errno?: number; message?: string }) => {
        // ER_SECURE_TRANSPORT_REQUIRED: tell the admin the fix instead of a bare refusal.
        if (err.errno === 3159) throw new Error(`${err.message} — ${MYSQL_TLS_HINT}`);
        throw err;
      });
    try {
      const [rows] = await conn.query("SELECT CURRENT_USER() AS u, VERSION() AS v");
      const row = (rows as { u: string; v: string }[])[0];
      return { ok: true, message: `Connected as ${row?.u} (MySQL ${row?.v})` };
    } finally {
      await conn.end();
    }
  },
  async mongodb(secret, config) {
    const target = parseMongoUri(secret);
    const client = new MongoClient(secret, {
      serverSelectionTimeoutMS: TIMEOUT_MS,
      // A single host is tested directly; replica sets and mongodb+srv go through normal discovery.
      ...(!target.srv && target.hosts.length === 1 ? { directConnection: true } : {}),
      // System roots plus the test-only extra CA (a CA file alone would replace the public roots).
      ...(tlsWanted(config) && upstreamCa(config.caCert) ? { ca: upstreamCa(config.caCert) } : {}),
    });
    try {
      await client.connect();
      await client.db().command({ ping: 1 });
      return { ok: true, message: "Connected and authenticated (ping ok)" };
    } finally {
      await client.close(true);
    }
  },
  async redis(secret, config) {
    const client = new Redis(secret, {
      lazyConnect: true,
      connectTimeout: TIMEOUT_MS,
      maxRetriesPerRequest: 0,
      retryStrategy: () => null,
      ...(tlsWanted(config) ? { tls: { ca: upstreamCa(config.caCert) } } : {}),
    });
    client.on("error", () => undefined);
    try {
      await client.connect();
      const pong = await client.ping();
      return {
        ok: pong === "PONG",
        message: pong === "PONG" ? "Connected and authenticated (PONG)" : `Unexpected reply ${pong}`,
      };
    } finally {
      client.disconnect();
    }
  },
  async smtp(secret, config) {
    const transport = nodemailer.createTransport(secret, { tls: { ca: upstreamCa(config.caCert) } } as never);
    try {
      await withTimeout(transport.verify(), "SMTP login");
      return { ok: true, message: "Mail server accepted the login" };
    } finally {
      transport.close();
    }
  },
  async http(secret, config) {
    // An authenticated path when the preset knows one (a bare "/" often answers 404 whatever the key).
    const path = String(config.testPath ?? config.basePath ?? "");
    const base = `${String(config.upstreamUrl ?? "").replace(/\/$/, "")}${path}`;
    const basicUser = typeof config.basicUser === "string" ? config.basicUser : "";
    const headers = injectCredential(
      (config.authScheme as AuthScheme | undefined) ?? "bearer",
      {
        "user-agent": "cb-connection-test",
        ...((config.extraHeaders as Record<string, string> | undefined) ?? {}),
        // Basic auth: the key ID (public) is the username, the stored secret the password.
        ...(basicUser ? { authorization: `Basic ${Buffer.from(`${basicUser}:`).toString("base64")}` } : {}),
      },
      secret,
      config.authHeader as string | undefined,
    );
    const res = await request(base || "/", {
      method: "GET",
      headers,
      dispatcher: upstreamDispatcher(config.caCert),
    });
    await res.body.dump();
    // On an authenticated test path some APIs answer a bad key with 400 (Gemini: API_KEY_INVALID).
    const rejected = [401, 403, ...(config.testPath ? [400] : [])];
    if (rejected.includes(res.statusCode))
      return { ok: false, message: `The API rejected the key (HTTP ${res.statusCode})` };
    return {
      ok: true,
      message: `Reachable; key not rejected (HTTP ${res.statusCode} for GET ${new URL(base).pathname || "/"})`,
    };
  },
  async oauth(secret, config) {
    const tokenUrl = new URL(String(config.tokenUrl));
    const target = new URL(
      tokenUrl.pathname,
      config.upstreamUrl ? String(config.upstreamUrl) : tokenUrl.origin,
    );
    const res = await request(target, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
      body: new URLSearchParams({
        grant_type: "client_credentials",
        client_id: "cb-connection-test",
        client_secret: secret,
      }).toString(),
      dispatcher: upstreamDispatcher(),
    });
    await res.body.dump();
    return res.statusCode < 500
      ? {
          ok: true,
          message: `Token endpoint reachable (HTTP ${res.statusCode}); the secret is verified on the first real sign-in`,
        }
      : { ok: false, message: `Token endpoint error (HTTP ${res.statusCode})` };
  },
  async aws(secret, config) {
    const keys = JSON.parse(secret) as { accessKeyId: string; secretAccessKey: string };
    const endpoint = new URL(String(config.endpoint));
    const signer = new SignatureV4({
      credentials: keys,
      region: String(config.region ?? "us-east-1"),
      service: "s3",
      sha256: Hash.bind(null, "sha256"),
    });
    const signed = await signer.sign(
      new HttpRequest({
        method: "GET",
        protocol: endpoint.protocol,
        hostname: endpoint.hostname,
        port: endpoint.port ? Number(endpoint.port) : undefined,
        path: "/",
        headers: { host: endpoint.host, "x-amz-content-sha256": "UNSIGNED-PAYLOAD" },
      }),
    );
    const res = await request(`${endpoint.origin}/`, {
      method: "GET",
      headers: signed.headers as Record<string, string>,
      dispatcher: upstreamDispatcher(),
    });
    const body = await res.body.text();
    if (res.statusCode === 200) return { ok: true, message: "Signed request accepted (ListBuckets ok)" };
    const code = /<Code>([^<]+)<\/Code>/.exec(body)?.[1];
    return { ok: false, message: `Request rejected (HTTP ${res.statusCode}${code ? ` ${code}` : ""})` };
  },
  async "google-sa"(secret, config) {
    const sa = JSON.parse(secret) as {
      client_email: string;
      private_key: string;
      private_key_id?: string;
      token_uri?: string;
    };
    const tokenUri = sa.token_uri ?? String(config.tokenUri ?? "https://oauth2.googleapis.com/token");
    const now = Math.floor(Date.now() / 1000);
    const assertion = signJwt(
      "RS256",
      sa.private_key,
      {
        iss: sa.client_email,
        scope: "https://www.googleapis.com/auth/cloud-platform",
        aud: tokenUri,
        iat: now,
        exp: now + 300,
      },
      sa.private_key_id ? { kid: sa.private_key_id } : {},
    );
    const tokenUrl = new URL(tokenUri);
    const target = new URL(
      tokenUrl.pathname,
      config.upstreamUrl ? String(config.upstreamUrl) : tokenUrl.origin,
    );
    const res = await request(target, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
        assertion,
      }).toString(),
      dispatcher: upstreamDispatcher(),
    });
    const json = (await res.body.json().catch(() => ({}))) as { access_token?: string; error?: string };
    return res.statusCode === 200 && json.access_token
      ? { ok: true, message: `Google issued a token for ${sa.client_email}` }
      : {
          ok: false,
          message: `Token exchange failed (HTTP ${res.statusCode}${json.error ? ` ${json.error}` : ""})`,
        };
  },
  async apns(secret, config) {
    const jwt = signJwt(
      "ES256",
      secret,
      { iss: config.teamId, iat: Math.floor(Date.now() / 1000) },
      { kid: config.keyId },
    );
    const origin = config.upstreamUrl
      ? new URL(String(config.upstreamUrl)).origin
      : "https://api.sandbox.push.apple.com";
    const ca = upstreamCa();
    const session = http2.connect(origin, ca ? { ca } : {});
    try {
      const { status, body } = await withTimeout(
        new Promise<{ status: number; body: string }>((resolve, reject) => {
          session.once("error", reject);
          const stream = session.request({
            ":method": "POST",
            ":path": `/3/device/${"0".repeat(64)}`,
            authorization: `bearer ${jwt}`,
            "apns-topic": "cb.connection.test",
          });
          let status = 0;
          let body = "";
          stream.on("response", (h) => {
            status = Number(h[":status"]);
          });
          stream.on("data", (c: Buffer) => {
            body += c.toString();
          });
          stream.on("end", () => resolve({ status, body }));
          stream.on("error", reject);
          stream.end(JSON.stringify({ aps: {} }));
        }),
        "APNs request",
      );
      const reason = (() => {
        try {
          return (JSON.parse(body) as { reason?: string }).reason;
        } catch {
          return undefined;
        }
      })();
      // A dummy device token can only be refused *after* the provider token was accepted.
      if (status === 403) return { ok: false, message: `Apple rejected the key (${reason ?? "403"})` };
      return {
        ok: true,
        message: `Apple accepted the key (${reason ?? `HTTP ${status}`} for a test device)`,
      };
    } finally {
      session.close();
    }
  },
  /**
   * No provider API can check a webhook signing secret (only a real delivery can), so the test checks its shape;
   * the first real webhook proves it (a mismatch shows as a rejected delivery in the dashboard).
   */
  async webhook(secret, config) {
    if (config.provider === "stripe" && !secret.startsWith("whsec_"))
      return { ok: false, message: "A Stripe signing secret starts with whsec_." };
    if (secret.trim().length < 8) return { ok: false, message: "The signing secret is too short." };
    return { ok: true, message: "Signing secret saved; the first webhook from the provider confirms it." };
  },
};

/** J2: test credentials that are not saved yet (Save & test, Replace value). No DB access, no audit. */
export async function runDraftTest(
  kind: ResourceKind,
  secret: string,
  config: Record<string, unknown>,
): Promise<{ ok: boolean; latencyMs: number; message: string }> {
  const started = Date.now();
  let outcome: Outcome;
  try {
    outcome = await withTimeout(testers[kind](secret, config), "Connection test");
  } catch (err) {
    outcome = { ok: false, message: err instanceof Error ? err.message : String(err) };
  }
  return { ok: outcome.ok, latencyMs: Date.now() - started, message: scrub(outcome.message, secret) };
}

/** J2 "test connection": connect from the gateway with the real credentials of a profile and report the outcome. */
export async function testResource(
  actorId: string,
  resourceId: Types.ObjectId,
  profile = DEFAULT_PROFILE,
): Promise<ResourceTestDto> {
  const resource = await ResourceModel.findById(resourceId).lean();
  if (!resource) throw new AppError("NOT_FOUND", { message: "Resource not found." });
  await requireMembership(actorId, resource.orgId, "admin");
  const secret =
    profile === DEFAULT_PROFILE
      ? await readResourceSecret(resource._id)
      : await readProfileSecret(resource._id, profile);
  if (secret === undefined) throw new AppError("NOT_FOUND", { message: `Profile "${profile}" not found.` });
  const draft = await runDraftTest(
    resource.kind as ResourceKind,
    secret,
    (resource.config as Record<string, unknown>) ?? {},
  );
  const result: ResourceTestDto = { ...draft, profile };
  await recordAudit({
    orgId: resource.orgId,
    actorId,
    projectId: resource.projectId,
    environmentId: resource.environmentId,
    resourceId: resource._id,
    action: "resource.tested",
    outcome: result.ok ? "success" : "error",
    target: `${resource.name}/${profile}`,
    meta: { latencyMs: result.latencyMs },
  });
  return result;
}
