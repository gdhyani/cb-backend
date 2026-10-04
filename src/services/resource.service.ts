import type { Types } from "mongoose";
import { z } from "zod";
import { getEnv } from "../config/env.js";
import { decryptSecret, encryptSecret } from "../crypto/envelope.js";
import { AppError } from "../errors/app-error.js";
import { type ResourceKind, ResourceModel } from "../models/resource.model.js";
import { VariableModel } from "../models/variable.model.js";
import {
  parseMongoUri,
  parseMysqlUri,
  parsePostgresUri,
  parseRedisUri,
  parseSmtpUri,
} from "../utils/connection-uri.js";
import { loadEnvironment, requireMembership } from "./access.service.js";
import { recordAudit } from "./audit.service.js";
import { touchEnvironment } from "./environment.service.js";

/** Which variable fields each resource kind can broker. */
export const BROKERED_FIELDS: Record<ResourceKind, readonly string[]> = {
  mongodb: ["url"],
  redis: ["url"],
  postgres: ["url"],
  mysql: ["url"],
  smtp: ["url", "host", "port", "user", "password"],
  http: ["key", "baseUrl"],
  oauth: ["clientSecret"],
};

const HostPort = z.string().regex(/^[a-z0-9.-]+:\d{1,5}$/i, "use host:port, e.g. api.stripe.com:443");
const Name = z.string().trim().min(1).max(60);

export const CreateResourceBody = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("mongodb"), name: Name, connectionUri: z.string().min(10) }),
  z.object({ kind: z.literal("redis"), name: Name, connectionUri: z.string().min(8) }),
  z.object({ kind: z.literal("postgres"), name: Name, connectionUri: z.string().min(10) }),
  z.object({ kind: z.literal("mysql"), name: Name, connectionUri: z.string().min(8) }),
  z.object({ kind: z.literal("smtp"), name: Name, connectionUri: z.string().min(8) }),
  z.object({
    kind: z.literal("http"),
    name: Name,
    upstreamUrl: z.url().refine((u) => u.startsWith("https://"), "must be an https:// URL"),
    authScheme: z.enum(["bearer", "x-api-key", "basic-password"]).default("bearer"),
    apiKey: z.string().min(1),
    fakePrefix: z.string().max(20).default("cb_"),
    basePath: z
      .string()
      .regex(/^(\/[^\s]*)?$/, "must start with /")
      .default(""),
    redirectHosts: z.array(HostPort).max(10).default([]),
  }),
  z.object({
    kind: z.literal("oauth"),
    name: Name,
    tokenUrl: z.url().refine((u) => u.startsWith("https://"), "must be an https:// URL"),
    clientSecret: z.string().min(1),
    upstreamUrl: z.url().optional(),
    redirectHosts: z.array(HostPort).max(10).optional(),
  }),
]);

export const UpdateResourceBody = z.object({
  name: Name.optional(),
  connectionUri: z.string().min(8).optional(),
  apiKey: z.string().min(1).optional(),
  upstreamUrl: z.url().optional(),
  authScheme: z.enum(["bearer", "x-api-key", "basic-password"]).optional(),
  fakePrefix: z.string().max(20).optional(),
  basePath: z.string().optional(),
  redirectHosts: z.array(HostPort).max(10).optional(),
  disabled: z.boolean().optional(),
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
function configAndSecret(
  kind: ResourceKind,
  input: Record<string, unknown>,
  current: Record<string, unknown> = {},
) {
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
    if (!uri) return { config: current, secret: undefined };
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
    // Host is shown to admins; credentials never are.
    const config = {
      host: `${parsed.host}:${parsed.port}`,
      database: parsed.database || defaultDb,
      tls:
        ["rediss", "smtps"].includes(parsed.protocol) ||
        parsed.params.get("tls") === "true" ||
        ["require", "verify-ca", "verify-full"].includes(sslmode),
    };
    return { config, secret: uri };
  }
  const config = { ...current };
  for (const key of ["upstreamUrl", "authScheme", "fakePrefix", "basePath", "redirectHosts"]) {
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
  await touchEnvironment(envId);
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
  const update: Record<string, unknown> = { config };
  if (input.name) update.name = input.name;
  if (secret)
    Object.assign(update, { credentials: encryptSecret(masterKey(), secret), rotatedAt: new Date() });
  if (input.disabled !== undefined) update.disabledAt = input.disabled ? new Date() : null;
  const updated = await ResourceModel.findByIdAndUpdate(resourceId, update, {
    returnDocument: "after",
  }).lean();
  if (!updated) throw new AppError("NOT_FOUND", { message: "Resource not found." });
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
  await ResourceModel.deleteOne({ _id: resourceId });
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

/** Gateway-only: decrypts the real credential for one use (FR-GW-005). Never returned by any API. */
export async function readResourceSecret(resourceId: Types.ObjectId): Promise<string> {
  const doc = await ResourceModel.findById(resourceId).select("+credentials").lean();
  if (!doc?.credentials) throw new AppError("NOT_FOUND", { message: "Resource credentials not found." });
  return decryptSecret(masterKey(), doc.credentials);
}
