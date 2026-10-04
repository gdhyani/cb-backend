import { X509Certificate } from "node:crypto";
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
import { loadEnvironment, requireMembership } from "./access.service.js";
import { recordAudit } from "./audit.service.js";
import { touchEnvironment } from "./environment.service.js";
import { readResourceSecret } from "./resource-secret.service.js";
import { runDraftTest } from "./resource-test.service.js";

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
  "google-sa": ["credentialsJson", "projectId", "clientEmail", "privateKey"],
  apns: ["key", "keyId", "teamId"],
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
      apiKey: z.string().min(1),
      fakePrefix: z.string().max(20).default("cb_"),
      basePath: z
        .string()
        .regex(/^(\/[^\s]*)?$/, "must start with /")
        .default(""),
      redirectHosts: z.array(HostPort).max(10).default([]),
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
      kind: z.literal("oauth"),
      name: Name,
      tokenUrl: HttpsOnlyUrl,
      clientSecret: z.string().min(1),
      upstreamUrl: UpstreamUrl.optional(),
      redirectHosts: z.array(HostPort).max(10).optional(),
    }),
  ])
  .superRefine((b, ctx) => {
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
  /** "" removes a previously stored CA certificate. */
  caCert: PemCertificates.or(z.literal("")).optional(),
  apiKey: z.string().min(1).optional(),
  upstreamUrl: UpstreamUrl.optional(),
  authScheme: AuthSchemeEnum.optional(),
  authHeader: AuthHeader.optional(),
  fakePrefix: z.string().max(20).optional(),
  basePath: z.string().optional(),
  redirectHosts: z.array(HostPort).max(10).optional(),
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
}

const masterKey = () => Buffer.from(getEnv().MASTER_KEY, "base64");

function toDto(r: {
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
  };
}

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
    "fakePrefix",
    "basePath",
    "redirectHosts",
  ]) {
    if (input[key] !== undefined)
      config[key] =
        key === "redirectHosts" ? (input[key] as string[]).map((h) => h.toLowerCase()) : input[key];
  }
  return { config, secret: input.apiKey as string | undefined };
}

export async function listResources(userId: string, envId: Types.ObjectId): Promise<ResourceDto[]> {
  await loadEnvironment(userId, envId);
  const rows = await ResourceModel.find({ environmentId: envId }).sort({ createdAt: 1 }).lean();
  return rows.map(toDto);
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
  const { config, secret } = configAndSecret(input.kind, input);
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
  return toDto(resource);
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
  const { config, secret } = configAndSecret(kind, input, resource.config as Record<string, unknown>);
  if (input.test) {
    const candidate = secret ?? (await readResourceSecret(resourceId));
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
  return toDto(updated);
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
