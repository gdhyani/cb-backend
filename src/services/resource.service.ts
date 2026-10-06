import { randomBytes, X509Certificate } from "node:crypto";
import type { Types } from "mongoose";
import { z } from "zod";
import { getEnv } from "../config/env.js";
import { encryptSecret } from "../crypto/envelope.js";
import { AppError } from "../errors/app-error.js";
import { bus } from "../events/bus.js";
import { CredentialProfileModel } from "../models/credential-profile.model.js";
import { GrantModel } from "../models/grant.model.js";
import { type ResourceKind, ResourceModel } from "../models/resource.model.js";
import { VariableModel } from "../models/variable.model.js";
import {
  type MongoTarget,
  mysqlWantsTls,
  parseMongoUri,
  parseMysqlUri,
  parsePostgresUri,
  parseRedisUri,
  parseSmtpUri,
} from "../utils/connection-uri.js";
import { HttpsOnlyUrl, UpstreamUrl } from "../utils/upstream-url.js";
import { parseWebhookSecrets, serializeWebhookSecrets, type WebhookSecrets } from "../webhooks/secrets.js";
import { WEBHOOK_PROVIDERS } from "../webhooks/signing.js";
import { loadEnvironment, requireMembership } from "./access.service.js";
import { recordAudit } from "./audit.service.js";
import { touchEnvironment } from "./environment.service.js";
import { readResourceSecret } from "./resource-secret.service.js";

/** Which variable fields each resource kind can broker. */
export const BROKERED_FIELDS: Record<ResourceKind, readonly string[]> = {
  mongodb: ["url"],
  redis: ["url"],
  postgres: ["url"],
  mysql: ["url"],
  smtp: ["url", "host", "port", "user", "password"],
  http: ["key", "baseUrl"],
  oauth: ["clientSecret"],
  aws: ["accessKeyId", "secretAccessKey", "endpoint", "region"],
  "google-sa": ["credentialsJson", "credentialsFile", "projectId", "clientEmail", "privateKey"],
  apns: ["key", "keyId", "teamId"],
  // thinSecret: optional second key for apps that verify Stripe thin events with their own env var.
  webhook: ["secret", "thinSecret"],
};

/** The variable that carries a service's secret: the one the admin names in "Add variable" (D2). */
export const MAIN_FIELD: Record<ResourceKind, string> = {
  mongodb: "url",
  redis: "url",
  postgres: "url",
  mysql: "url",
  smtp: "url",
  http: "key",
  oauth: "clientSecret",
  aws: "secretAccessKey",
  "google-sa": "credentialsJson",
  apns: "key",
  webhook: "secret",
};

const GOOGLE_DEFAULT_HOSTS = ["oauth2.googleapis.com:443", "fcm.googleapis.com:443"];
const APNS_DEFAULT_HOSTS = ["api.push.apple.com:443", "api.sandbox.push.apple.com:443"];
const HttpsUrl = HttpsOnlyUrl;
const PemPrivateKey = z.string().refine((k) => k.includes("PRIVATE KEY-----"), "must be a PEM private key");

/** Public CA certificate(s) a self-hosted or private-CA database presents; trusted for that resource only. */
const PemCertificates = z
  .string()
  .max(32_000)
  .refine((pem) => {
    const blocks = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) ?? [];
    if (blocks.length === 0) return false;
    try {
      for (const b of blocks) new X509Certificate(b);
      return true;
    } catch {
      return false;
    }
  }, "must be one or more PEM certificates (-----BEGIN CERTIFICATE-----)");

/** A Google service-account JSON key file (Firebase Admin). */
const ServiceAccountJson = z.string().refine((raw) => {
  try {
    const sa = JSON.parse(raw) as Record<string, unknown>;
    return (
      typeof sa.client_email === "string" &&
      typeof sa.private_key === "string" &&
      typeof sa.project_id === "string"
    );
  } catch {
    return false;
  }
}, "must be a service-account JSON key with project_id, client_email and private_key");

const HostPort = z.string().regex(/^[a-z0-9.-]+:\d{1,5}$/i, "use host:port, e.g. api.stripe.com:443");
const Name = z.string().trim().min(1).max(60);
const AuthSchemeEnum = z.enum(["bearer", "x-api-key", "basic-password", "header"]);
const AuthHeader = z
  .string()
  .regex(/^[a-z0-9][a-z0-9-]{0,63}$/, "a lowercase header name, e.g. x-goog-api-key");
/** Where the agent posts webhooks inside the developer's app: a path only (always 127.0.0.1). */
const WebhookPath = z
  .string()
  .max(300)
  // "//host" would be protocol-relative (another host) for any client resolving it against a base URL.
  .regex(/^\/(?!\/)[^\s?#\\]*(\?[^\s#]*)?$/, "a path in your app, e.g. /api/webhooks/stripe");
const WebhookPort = z.number().int().min(1).max(65_535);
const WebhookProviderEnum = z.enum(WEBHOOK_PROVIDERS);
const SigningSecret = z.string().trim().min(8).max(500);
const StripeSecret = SigningSecret.refine(
  (v) => v.startsWith("whsec_"),
  "a Stripe signing secret starts with whsec_ (Developers → Webhooks → your destination)",
);

/** OQ9: non-secret headers sent on every call (e.g. OpenAI-Organization); never the credential or transport headers. */
const RESERVED_HEADERS = new Set([
  "authorization",
  "proxy-authorization",
  "x-api-key",
  "cookie",
  "host",
  "content-length",
  "transfer-encoding",
  "connection",
  "upgrade",
  "te",
  "keep-alive",
]);
const ExtraHeaders = z
  .record(
    z.string().regex(/^[A-Za-z0-9][A-Za-z0-9-]{0,63}$/, "a header name such as OpenAI-Organization"),
    z
      .string()
      .max(500)
      .regex(/^[^\r\n]*$/, "one line"),
  )
  .refine((h) => Object.keys(h).length <= 10, "at most 10 headers")
  .refine((h) => Object.keys(h).every((k) => !RESERVED_HEADERS.has(k.toLowerCase())), {
    message: "the key header, cookies and transport headers are set by cb",
  })
  .transform((h) => Object.fromEntries(Object.entries(h).map(([k, v]) => [k.toLowerCase(), v])));

/** UI hint only (which preset or dashboard type made this service); never read by the gateway. */
const Provider = z.string().regex(/^[a-z0-9-]{1,40}$/);

export const CreateResourceBody = z
  .discriminatedUnion("kind", [
    z.object({
      kind: z.literal("mongodb"),
      name: Name,
      connectionUri: z.string().min(10),
      caCert: PemCertificates.optional(),
    }),
    z.object({
      kind: z.literal("redis"),
      name: Name,
      connectionUri: z.string().min(8),
      caCert: PemCertificates.optional(),
    }),
    z.object({
      kind: z.literal("postgres"),
      name: Name,
      connectionUri: z.string().min(10),
      caCert: PemCertificates.optional(),
    }),
    z.object({
      kind: z.literal("mysql"),
      name: Name,
      connectionUri: z.string().min(8),
      caCert: PemCertificates.optional(),
    }),
    z.object({
      kind: z.literal("smtp"),
      name: Name,
      connectionUri: z.string().min(8),
      caCert: PemCertificates.optional(),
    }),
    z.object({
      kind: z.literal("http"),
      name: Name,
      upstreamUrl: UpstreamUrl,
      authScheme: AuthSchemeEnum.default("bearer"),
      authHeader: AuthHeader.optional(),
      provider: Provider.optional(),
      /** Authenticated GET used by Save & test (from the preset), e.g. /v1/models. */
      testPath: z
        .string()
        .regex(/^\/[^\s]*$/, "must start with /")
        .optional(),
      /** Basic auth: the public key ID sent as the username (Razorpay key_id). */
      basicUser: z.string().max(200).optional(),
      apiKey: z.string().min(1),
      fakePrefix: z.string().max(20).default("cb_"),
      basePath: z
        .string()
        .regex(/^(\/[^\s]*)?$/, "must start with /")
        .default(""),
      redirectHosts: z.array(HostPort).max(10).default([]),
      /** OQ9: internal APIs on a private CA. */
      caCert: PemCertificates.optional(),
      extraHeaders: ExtraHeaders.optional(),
    }),
    z.object({
      kind: z.literal("aws"),
      name: Name,
      region: z.string().regex(/^[a-z0-9-]+$/, "e.g. eu-west-1, or auto for R2"),
      // https for real endpoints; plain http only for private addresses (D11).
      endpoint: UpstreamUrl,
      accessKeyId: z.string().min(3),
      secretAccessKey: z.string().min(8),
    }),
    z.object({
      kind: z.literal("google-sa"),
      name: Name,
      serviceAccountJson: ServiceAccountJson,
      upstreamUrl: HttpsUrl.optional(),
      redirectHosts: z.array(HostPort).max(10).optional(),
    }),
    z.object({
      kind: z.literal("apns"),
      name: Name,
      keyId: z.string().regex(/^[A-Z0-9]{10}$/, "10-character key ID from Apple"),
      teamId: z.string().regex(/^[A-Z0-9]{10}$/, "10-character team ID from Apple"),
      privateKey: PemPrivateKey,
      upstreamUrl: HttpsUrl.optional(),
      redirectHosts: z.array(HostPort).max(10).optional(),
    }),
    z.object({
      kind: z.literal("webhook"),
      name: Name,
      provider: WebhookProviderEnum,
      path: WebhookPath,
      port: WebhookPort.optional(),
      /**
       * Optional: Stripe gets it from Connect (or a paste later); Razorpay's is generated by cb when left out and
       * returned once as `generatedSecret`.
       */
      signingSecret: SigningSecret.optional(),
      /** Stripe only: the thin-payload destination's secret (same cb URL, its own secret). */
      thinSigningSecret: StripeSecret.optional(),
      /** Stripe only: where thin events go in the app when it has a separate route (default: `path`). */
      thinPath: WebhookPath.optional(),
    }),
    z.object({
      kind: z.literal("oauth"),
      name: Name,
      tokenUrl: HttpsOnlyUrl,
      clientSecret: z.string().min(1),
      upstreamUrl: UpstreamUrl.optional(),
      redirectHosts: z.array(HostPort).max(10).optional(),
    }),
  ])
  .superRefine((b, ctx) => {
    if (
      b.kind === "webhook" &&
      b.provider === "stripe" &&
      b.signingSecret &&
      !b.signingSecret.startsWith("whsec_")
    )
      ctx.addIssue({
        code: "custom",
        path: ["signingSecret"],
        message: "a Stripe signing secret starts with whsec_ (Developers → Webhooks → your endpoint)",
      });
    if (b.kind === "webhook" && b.provider !== "stripe")
      for (const k of ["thinSigningSecret", "thinPath"] as const)
        if (b[k] !== undefined)
          ctx.addIssue({ code: "custom", path: [k], message: "thin events are Stripe only" });
    if (b.kind === "http" && b.extraHeaders && b.authHeader && b.authHeader in b.extraHeaders)
      ctx.addIssue({ code: "custom", path: ["extraHeaders"], message: "already carries the key" });
    if (b.kind === "http" && b.authScheme === "header" && !b.authHeader)
      ctx.addIssue({ code: "custom", path: ["authHeader"], message: "required with the named-header style" });
  });

export const UpdateResourceBody = z.object({
  serviceAccountJson: ServiceAccountJson.optional(),
  keyId: z
    .string()
    .regex(/^[A-Z0-9]{10}$/)
    .optional(),
  teamId: z
    .string()
    .regex(/^[A-Z0-9]{10}$/)
    .optional(),
  privateKey: PemPrivateKey.optional(),
  accessKeyId: z.string().min(3).optional(),
  secretAccessKey: z.string().min(8).optional(),
  region: z
    .string()
    .regex(/^[a-z0-9-]+$/)
    .optional(),
  endpoint: UpstreamUrl.optional(),
  clientSecret: z.string().min(1).optional(),
  tokenUrl: HttpsOnlyUrl.optional(),
  name: Name.optional(),
  connectionUri: z.string().min(8).optional(),
  signingSecret: SigningSecret.optional(),
  thinSigningSecret: StripeSecret.optional(),
  /** null: thin events go to `path` again. */
  thinPath: WebhookPath.nullable().optional(),
  /** Razorpay: replace the signing secret with a new generated one (returned once as `generatedSecret`). */
  regenerateSecret: z.literal(true).optional(),
  path: WebhookPath.optional(),
  /** null clears the default port. */
  port: WebhookPort.nullable().optional(),
  /** "" removes a previously stored CA certificate. */
  caCert: PemCertificates.or(z.literal("")).optional(),
  apiKey: z.string().min(1).optional(),
  upstreamUrl: UpstreamUrl.optional(),
  authScheme: AuthSchemeEnum.optional(),
  authHeader: AuthHeader.optional(),
  fakePrefix: z.string().max(20).optional(),
  basePath: z.string().optional(),
  redirectHosts: z.array(HostPort).max(10).optional(),
  /** OQ9: replaces the service's extra headers ({} removes them). */
  extraHeaders: ExtraHeaders.optional(),
  disabled: z.boolean().optional(),
  /** D9: test the merged credential/config before storing; 422 SERVICE_TEST_FAILED when it fails. */
  test: z.boolean().optional(),
});

export interface ResourceDto {
  id: string;
  environmentId: string;
  kind: ResourceKind;
  name: string;
  config: Record<string, unknown>;
  credentialsSet: boolean;
  rotatedAt: string | null;
  disabled: boolean;
  brokeredFields: readonly string[];
  createdAt: string;
  /** Webhook services: the URL to paste into the provider's webhook settings (FR-WH-001). */
  webhookUrl?: string;
  /**
   * Razorpay webhooks: the signing secret cb generated, in the create (or regenerate) answer only — the admin pastes
   * it into Razorpay once. Never readable afterwards (L15).
   */
  generatedSecret?: string;
}

const masterKey = () => Buffer.from(getEnv().MASTER_KEY, "base64");

export function webhookUrlOf(serviceId: string): string {
  const env = getEnv();
  const base = (env.PUBLIC_URL ?? `http://localhost:${env.PORT}`).replace(/\/+$/, "");
  return `${base}/api/hooks/${serviceId}`;
}

export function toResourceDto(r: {
  _id: Types.ObjectId;
  environmentId: Types.ObjectId;
  kind: string;
  name: string;
  config?: unknown;
  rotatedAt?: Date | null;
  disabledAt?: Date | null;
  createdAt?: Date;
}): ResourceDto {
  const kind = r.kind as ResourceKind;
  return {
    id: r._id.toHexString(),
    environmentId: r.environmentId.toHexString(),
    kind,
    name: r.name,
    config: (r.config as Record<string, unknown>) ?? {},
    credentialsSet: true,
    rotatedAt: r.rotatedAt?.toISOString() ?? null,
    disabled: Boolean(r.disabledAt),
    brokeredFields: BROKERED_FIELDS[kind],
    createdAt: (r.createdAt ?? new Date()).toISOString(),
    ...(kind === "webhook" ? { webhookUrl: webhookUrlOf(r._id.toHexString()) } : {}),
  };
}

/** Which signing secrets a webhook service has (shown to admins; the values never are). */
function withSecretsSet(config: Record<string, unknown>, s: WebhookSecrets): Record<string, unknown> {
  return { ...config, secretsSet: { snapshot: Boolean(s.snapshot), thin: Boolean(s.thin) } };
}

/** A Razorpay webhook secret made by cb: 32 random bytes, URL-safe. */
const generateWebhookSecret = () => randomBytes(32).toString("base64url");

/** Splits create/update input into non-secret config and the secret to encrypt. */
export function configAndSecret(
  kind: ResourceKind,
  input: Record<string, unknown>,
  current: Record<string, unknown> = {},
) {
  if (kind === "aws") {
    const config = {
      ...current,
      ...(input.region ? { region: input.region } : {}),
      ...(input.endpoint ? { endpoint: input.endpoint } : {}),
    };
    const secret =
      input.accessKeyId && input.secretAccessKey
        ? JSON.stringify({ accessKeyId: input.accessKeyId, secretAccessKey: input.secretAccessKey })
        : undefined;
    return { config, secret };
  }
  const hostsFrom = (fallback: string[]) =>
    (
      (input.redirectHosts as string[] | undefined) ??
      (current.redirectHosts as string[] | undefined) ??
      fallback
    ).map((h) => h.toLowerCase());
  const upstream = input.upstreamUrl ? { upstreamUrl: input.upstreamUrl } : {};
  if (kind === "google-sa") {
    const raw = input.serviceAccountJson as string | undefined;
    if (!raw)
      return {
        config: { ...current, ...upstream, redirectHosts: hostsFrom(GOOGLE_DEFAULT_HOSTS) },
        secret: undefined,
      };
    const sa = JSON.parse(raw) as { project_id: string; client_email: string; token_uri?: string };
    const tokenUri = sa.token_uri ?? "https://oauth2.googleapis.com/token";
    const fallback = [`${new URL(tokenUri).hostname}:443`, "fcm.googleapis.com:443"];
    // Only identifiers are kept in config; the private key lives in the encrypted secret.
    const config = {
      ...current,
      ...upstream,
      projectId: sa.project_id,
      clientEmail: sa.client_email,
      tokenUri,
      redirectHosts: [...new Set(hostsFrom(fallback))],
    };
    return { config, secret: raw };
  }
  if (kind === "apns") {
    const config = {
      ...current,
      ...upstream,
      ...(input.keyId ? { keyId: input.keyId } : {}),
      ...(input.teamId ? { teamId: input.teamId } : {}),
      redirectHosts: hostsFrom(APNS_DEFAULT_HOSTS),
    };
    return { config, secret: input.privateKey as string | undefined };
  }
  if (kind === "webhook") {
    const config: Record<string, unknown> = { ...current };
    if (input.provider) {
      config.provider = input.provider;
      config.fakePrefix = input.provider === "stripe" ? "whsec_" : "";
    }
    if (input.path !== undefined) config.path = input.path;
    if (input.port === null) delete config.port;
    else if (input.port !== undefined) config.port = input.port;
    if (input.thinPath === null) delete config.thinPath;
    else if (input.thinPath !== undefined) config.thinPath = input.thinPath;
    const given = input.signingSecret !== undefined || input.thinSigningSecret !== undefined;
    // Create input only; updates merge with the stored secrets (see webhookSecretUpdate).
    const secrets: WebhookSecrets = {
      snapshot: input.signingSecret as string | undefined,
      thin: input.thinSigningSecret as string | undefined,
    };
    return given
      ? { config: withSecretsSet(config, secrets), secret: serializeWebhookSecrets(secrets) }
      : { config, secret: undefined };
  }
  if (kind === "oauth") {
    const tokenUrl = (input.tokenUrl as string | undefined) ?? (current.tokenUrl as string | undefined) ?? "";
    const hosts =
      (input.redirectHosts as string[] | undefined) ??
      (current.redirectHosts as string[] | undefined) ??
      (tokenUrl ? [`${new URL(tokenUrl).hostname}:443`] : []);
    const config = {
      ...current,
      tokenUrl,
      redirectHosts: hosts.map((h) => h.toLowerCase()),
      ...(input.upstreamUrl ? { upstreamUrl: input.upstreamUrl } : {}),
    };
    return { config, secret: input.clientSecret as string | undefined };
  }
  if (kind !== "http") {
    const uri = input.connectionUri as string | undefined;
    // CA certificate: kept across updates, replaced when given, removed with "".
    const withCa = (config: Record<string, unknown>) => {
      const ca = input.caCert === undefined ? current.caCert : input.caCert;
      const { caCert: _drop, ...rest } = config;
      return ca ? { ...rest, caCert: ca } : rest;
    };
    if (!uri) return { config: withCa(current), secret: undefined };
    const parse = {
      mongodb: parseMongoUri,
      redis: parseRedisUri,
      postgres: parsePostgresUri,
      mysql: parseMysqlUri,
      smtp: parseSmtpUri,
    }[kind];
    const parsed = parse(uri);
    const defaultDb = {
      mongodb: "test",
      redis: "0",
      postgres: parsed.username ?? "postgres",
      mysql: "",
      smtp: "",
    }[kind];
    const sslmode = parsed.params.get("sslmode") ?? "";
    const mongo = kind === "mongodb" ? (parsed as MongoTarget) : undefined;
    const config = {
      // Shown to admins; credentials never are. Replica sets list every member; mongodb+srv shows the SRV name.
      host: mongo?.srv
        ? mongo.hosts[0]?.host
        : mongo && mongo.hosts.length > 1
          ? mongo.hosts.map((h) => `${h.host}:${h.port}`).join(",")
          : `${parsed.host}:${parsed.port}`,
      database: parsed.database || defaultDb,
      tls:
        (mongo?.srv === true &&
          !["false"].includes(parsed.params.get("tls") ?? parsed.params.get("ssl") ?? "")) ||
        ["rediss", "smtps"].includes(parsed.protocol) ||
        (kind === "mysql" && mysqlWantsTls(parsed.params)) ||
        parsed.params.get("tls") === "true" ||
        ["require", "verify-ca", "verify-full"].includes(sslmode),
    };
    return { config: withCa(config), secret: uri };
  }
  const config = { ...current };
  for (const key of [
    "upstreamUrl",
    "authScheme",
    "authHeader",
    "provider",
    "testPath",
    "basicUser",
    "fakePrefix",
    "basePath",
    "redirectHosts",
    "extraHeaders",
  ]) {
    if (input[key] !== undefined)
      config[key] =
        key === "redirectHosts" ? (input[key] as string[]).map((h) => h.toLowerCase()) : input[key];
  }
  // OQ9: CA certificate kept across updates, replaced when given, removed with "".
  if (input.caCert !== undefined) {
    if (input.caCert) config.caCert = input.caCert;
    else delete config.caCert;
  }
  return { config, secret: input.apiKey as string | undefined };
}

export async function listResources(userId: string, envId: Types.ObjectId): Promise<ResourceDto[]> {
  await loadEnvironment(userId, envId);
  const rows = await ResourceModel.find({ environmentId: envId }).sort({ createdAt: 1 }).lean();
  return rows.map(toResourceDto);
}

export async function createResource(
  actorId: string,
  envId: Types.ObjectId,
  input: z.infer<typeof CreateResourceBody>,
  opts: { touch?: boolean } = {},
): Promise<ResourceDto> {
  const { env } = await loadEnvironment(actorId, envId, "admin");
  if (await ResourceModel.exists({ environmentId: envId, name: input.name })) {
    throw new AppError("CONFLICT", {
      message: `A resource named "${input.name}" already exists in this environment.`,
    });
  }
  let { config, secret } = configAndSecret(input.kind, input);
  let generatedSecret: string | undefined;
  if (input.kind === "webhook" && !secret) {
    // Razorpay: cb picks the secret; Stripe: Connect (or a paste) adds it later. Webhooks are refused until then.
    const secrets: WebhookSecrets = {};
    if (input.provider === "razorpay") secrets.snapshot = generatedSecret = generateWebhookSecret();
    config = withSecretsSet(config, secrets);
    secret = serializeWebhookSecrets(secrets);
  }
  if (!secret) throw new AppError("VALIDATION_FAILED", { message: "Credentials are required." });
  const resource = await ResourceModel.create({
    orgId: env.orgId,
    projectId: env.projectId,
    environmentId: envId,
    kind: input.kind,
    name: input.name,
    config,
    credentials: encryptSecret(masterKey(), secret),
    rotatedAt: new Date(),
  });
  if (opts.touch !== false) await touchEnvironment(envId);
  await recordAudit({
    orgId: env.orgId,
    actorId,
    projectId: env.projectId,
    environmentId: envId,
    resourceId: resource._id,
    action: "resource.created",
    target: `${input.kind}:${input.name}`,
  });
  return { ...toResourceDto(resource), ...(generatedSecret ? { generatedSecret } : {}) };
}

async function loadResource(actorId: string, resourceId: Types.ObjectId, minRole: "developer" | "admin") {
  const resource = await ResourceModel.findById(resourceId).lean();
  if (!resource) throw new AppError("NOT_FOUND", { message: "Resource not found." });
  await requireMembership(actorId, resource.orgId, minRole);
  return resource;
}

export async function updateResource(
  actorId: string,
  resourceId: Types.ObjectId,
  input: z.infer<typeof UpdateResourceBody>,
): Promise<ResourceDto> {
  const resource = await loadResource(actorId, resourceId, "admin");
  const kind = resource.kind as ResourceKind;
  const current = (resource.config ?? {}) as Record<string, unknown>;
  const { config: merged, secret: given } = configAndSecret(kind, input, current);
  let config = merged as Record<string, unknown>;
  let secret = given;
  let generatedSecret: string | undefined;
  if (
    kind === "webhook" &&
    current.provider !== "stripe" &&
    (input.thinSigningSecret !== undefined || input.thinPath !== undefined)
  )
    throw new AppError("VALIDATION_FAILED", { message: "Thin events are Stripe only." });
  if (kind === "webhook" && (given || input.regenerateSecret)) {
    // Only what was sent changes: a new thin secret keeps the snapshot secret and the other way round.
    const stored = parseWebhookSecrets(await readResourceSecret(resourceId));
    const next: WebhookSecrets = {
      snapshot: input.signingSecret ?? stored.snapshot,
      thin: input.thinSigningSecret ?? stored.thin,
    };
    if (input.regenerateSecret) {
      if (current.provider !== "razorpay")
        throw new AppError("VALIDATION_FAILED", {
          message: "Only Razorpay webhook secrets are generated by cb.",
        });
      next.snapshot = generatedSecret = generateWebhookSecret();
    }
    config = withSecretsSet(config, next);
    secret = serializeWebhookSecrets(next);
  }
  // M1: the merged config must stay usable.
  if (kind === "http" && config.authScheme === "header" && !config.authHeader)
    throw new AppError("VALIDATION_FAILED", {
      details: [{ path: "authHeader", message: "required with the named-header style" }],
    });
  // I5: sending the stored key somewhere new needs the key again (no one can redirect a secret they can't see).
  const SECRET_FIELD: Partial<Record<ResourceKind, string>> = {
    http: "apiKey",
    oauth: "clientSecret",
    aws: "secretAccessKey",
    "google-sa": "serviceAccountJson",
    apns: "privateKey",
    webhook: "signingSecret",
  };
  const host = (u: unknown) => {
    try {
      return new URL(String(u)).host;
    } catch {
      return "";
    }
  };
  const moved = ["upstreamUrl", "endpoint", "tokenUrl"].some(
    (k) => k in input && input[k as keyof typeof input] !== undefined && host(config[k]) !== host(current[k]),
  );
  if (moved && !secret)
    throw new AppError("VALIDATION_FAILED", {
      message: "Changing where the key is sent needs the key again.",
      details: [
        {
          path: SECRET_FIELD[kind] ?? "credentials",
          message: "Enter the key again to send it to the new address.",
        },
      ],
    });
  if (input.test) {
    const candidate = secret ?? (await readResourceSecret(resourceId));
    // Loaded lazily: resource-test → profile → resource would otherwise be a load-order-dependent cycle.
    const { runDraftTest } = await import("./resource-test.service.js");
    const result = await runDraftTest(kind, candidate, config);
    if (!result.ok) throw new AppError("SERVICE_TEST_FAILED", { message: result.message });
  }
  const update: Record<string, unknown> = { config };
  if (input.name) update.name = input.name;
  if (secret)
    Object.assign(update, { credentials: encryptSecret(masterKey(), secret), rotatedAt: new Date() });
  if (input.disabled !== undefined) update.disabledAt = input.disabled ? new Date() : null;
  const updated = await ResourceModel.findByIdAndUpdate(resourceId, update, {
    returnDocument: "after",
  }).lean();
  if (!updated) throw new AppError("NOT_FOUND", { message: "Resource not found." });
  if (input.disabled === true)
    bus.publish({
      type: "access.revoked",
      scope: "resource",
      resourceId: resourceId.toHexString(),
      reason: "service disabled",
    });
  await touchEnvironment(resource.environmentId);
  await recordAudit({
    orgId: resource.orgId,
    actorId,
    projectId: resource.projectId,
    environmentId: resource.environmentId,
    resourceId,
    action: secret ? "resource.rotated" : "resource.updated",
    target: updated.name,
  });
  return { ...toResourceDto(updated), ...(generatedSecret ? { generatedSecret } : {}) };
}

export async function deleteResource(actorId: string, resourceId: Types.ObjectId): Promise<void> {
  const resource = await loadResource(actorId, resourceId, "admin");
  await VariableModel.deleteMany({ resourceId });
  await CredentialProfileModel.deleteMany({ resourceId });
  await ResourceModel.deleteOne({ _id: resourceId });
  await GrantModel.updateMany(
    { "resourceProfiles.resourceId": resourceId },
    { $pull: { resourceProfiles: { resourceId } } },
  );
  bus.publish({
    type: "access.revoked",
    scope: "resource",
    resourceId: resourceId.toHexString(),
    reason: "service removed",
  });
  await touchEnvironment(resource.environmentId);
  await recordAudit({
    orgId: resource.orgId,
    actorId,
    projectId: resource.projectId,
    environmentId: resource.environmentId,
    action: "resource.deleted",
    target: resource.name,
  });
}
