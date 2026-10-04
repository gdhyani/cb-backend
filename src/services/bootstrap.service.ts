import type { Types } from "mongoose";
import { z } from "zod";
import { getEnv } from "../config/env.js";
import { decryptSecret } from "../crypto/envelope.js";
import { AppError } from "../errors/app-error.js";
import { EnvironmentModel } from "../models/environment.model.js";
import { ProjectModel } from "../models/project.model.js";
import { ResourceModel } from "../models/resource.model.js";
import { VariableModel } from "../models/variable.model.js";
import { assertRuntimeAccess, requireMembership } from "./access.service.js";
import { recordAudit } from "./audit.service.js";
import {
  fakeApiKey,
  fakeApnsKey,
  fakeAwsKeys,
  fakeDbCredentials,
  fakeGoogleKey,
  fakeRedisCredentials,
} from "./fakes.service.js";
import { ensureOrgCa } from "./org-ca.service.js";
import { generatedValue } from "./variable.service.js";

export const BootstrapQuery = z.object({
  projectId: z.string().min(1),
  env: z.string().min(1),
  orgId: z.string().optional(),
});

/** Draft bootstrap contract (tunnel-protocol, M0). `{port}` is replaced by the agent's local port. */
export interface BootstrapDto {
  schema: 1;
  version: number;
  orgId: string;
  projectId: string;
  projectSlug: string;
  environment: string;
  envId: string;
  orgCaCert: string;
  plain: Record<string, string>;
  listeners: { resourceId: string; kind: string; name: string; env: Record<string, string> }[];
  redirects: { host: string; port: number; resourceId: string }[];
  visibleKeys: string[];
}

interface HttpConfig {
  fakePrefix?: string;
  basePath?: string;
  redirectHosts?: string[];
}

export async function resolveEnvironment(userId: string, query: z.infer<typeof BootstrapQuery>) {
  const isId = /^[a-f0-9]{24}$/.test(query.projectId);
  const project = await ProjectModel.findOne(
    isId
      ? { _id: query.projectId }
      : { slug: query.projectId.toLowerCase(), ...(query.orgId ? { orgId: query.orgId } : {}) },
  ).lean();
  if (!project) throw new AppError("NOT_FOUND", { message: `Project "${query.projectId}" not found.` });
  await requireMembership(userId, project.orgId);
  const env = await EnvironmentModel.findOne({
    projectId: project._id,
    name: query.env.toLowerCase(),
  }).lean();
  if (!env)
    throw new AppError("NOT_FOUND", { message: `Environment "${query.env}" not found in ${project.name}.` });
  return { project, env };
}

/** FR-AGT-003: everything a device needs to run the app — fake, personal and plain values only (S1). */
export async function buildBootstrap(
  auth: { userId: string; deviceId: string },
  query: z.infer<typeof BootstrapQuery>,
): Promise<BootstrapDto> {
  const { project, env } = await resolveEnvironment(auth.userId, query);
  try {
    await assertRuntimeAccess(auth.userId, env, { deviceId: auth.deviceId });
  } catch (err) {
    await recordAudit({
      orgId: env.orgId,
      actorId: auth.userId,
      deviceId: auth.deviceId,
      projectId: project._id,
      environmentId: env._id,
      action: "agent.bootstrap",
      outcome: "denied",
      meta: { reason: err instanceof AppError ? err.code : "error" },
    });
    throw err;
  }
  const envId = env._id.toHexString();
  const [variables, resources, orgCaCert] = await Promise.all([
    VariableModel.find({ environmentId: env._id }).select("+secret").lean(),
    ResourceModel.find({ environmentId: env._id, disabledAt: null }).lean(),
    ensureOrgCa(env.orgId),
  ]);
  const resourceById = new Map(resources.map((r) => [r._id.toHexString(), r] as const));
  const masterKey = Buffer.from(getEnv().MASTER_KEY, "base64");

  const plain: Record<string, string> = {};
  const visibleKeys: string[] = [];
  const listeners = new Map<string, BootstrapDto["listeners"][number]>();
  const redirects = new Map<string, BootstrapDto["redirects"][number]>();
  const listenerFor = (r: (typeof resources)[number]) => {
    const id = r._id.toHexString();
    let l = listeners.get(id);
    if (!l) {
      l = { resourceId: id, kind: r.kind, name: r.name, env: {} };
      listeners.set(id, l);
    }
    return l;
  };

  const redirectFor = (r: (typeof resources)[number]) => {
    for (const hp of ((r.config ?? {}) as { redirectHosts?: string[] }).redirectHosts ?? []) {
      const i = hp.lastIndexOf(":");
      redirects.set(hp, {
        host: hp.slice(0, i),
        port: Number(hp.slice(i + 1)),
        resourceId: r._id.toHexString(),
      });
    }
  };

  for (const v of variables) {
    switch (v.type) {
      case "plain":
        plain[v.key] = v.value ?? "";
        break;
      case "generated":
        plain[v.key] = generatedValue(auth.userId, envId, v._id.toHexString(), v.format ?? "hex:32");
        break;
      case "visible":
        if (v.secret) {
          plain[v.key] = decryptSecret(masterKey, v.secret);
          visibleKeys.push(v.key);
        }
        break;
      case "brokered": {
        const r = v.resourceId ? resourceById.get(v.resourceId.toHexString()) : undefined;
        if (!r) break;
        const scope = { deviceId: auth.deviceId, environmentId: envId, resourceId: r._id.toHexString() };
        const config = (r.config ?? {}) as Record<string, unknown> & HttpConfig;
        if (r.kind === "mongodb" && v.field === "url") {
          listenerFor(r).env[v.key] =
            `mongodb://127.0.0.1:{port}/${String(config.database ?? "test")}?directConnection=true`;
        } else if (r.kind === "redis" && v.field === "url") {
          const fake = fakeRedisCredentials(scope);
          const db = config.database && config.database !== "0" ? `/${String(config.database)}` : "";
          listenerFor(r).env[v.key] = `redis://${fake.username}:${fake.password}@127.0.0.1:{port}${db}`;
        } else if (r.kind === "postgres" && v.field === "url") {
          const fake = fakeDbCredentials(scope);
          listenerFor(r).env[v.key] =
            `postgresql://${fake.username}:${fake.password}@127.0.0.1:{port}/${String(config.database ?? "")}?sslmode=disable`;
        } else if (r.kind === "mysql" && v.field === "url") {
          const fake = fakeDbCredentials(scope);
          listenerFor(r).env[v.key] =
            `mysql://${fake.username}:${fake.password}@127.0.0.1:{port}/${String(config.database ?? "")}`;
        } else if (r.kind === "smtp") {
          const fake = fakeDbCredentials(scope);
          const value = {
            url: `smtp://${fake.username}:${fake.password}@127.0.0.1:{port}`,
            host: "127.0.0.1",
            port: "{port}",
            user: fake.username,
            password: fake.password,
          }[v.field ?? "url"];
          // Every SMTP field needs the listener; only host/port/url carry the port placeholder.
          if (value !== undefined) listenerFor(r).env[v.key] = value;
        } else if (r.kind === "http" && v.field === "baseUrl") {
          listenerFor(r).env[v.key] = `http://127.0.0.1:{port}${config.basePath ?? ""}`;
        } else if (r.kind === "aws") {
          const fake = fakeAwsKeys(scope);
          if (v.field === "endpoint") listenerFor(r).env[v.key] = "http://127.0.0.1:{port}";
          else if (v.field === "region") plain[v.key] = String(config.region ?? "us-east-1");
          else if (v.field === "accessKeyId") plain[v.key] = fake.accessKeyId;
          else if (v.field === "secretAccessKey") plain[v.key] = fake.secretAccessKey;
        } else if (r.kind === "google-sa") {
          const sa = config as unknown as { projectId: string; clientEmail: string; tokenUri: string };
          const value = async () => {
            if (v.field === "projectId") return sa.projectId;
            if (v.field === "clientEmail") return sa.clientEmail;
            const { privatePem } = await fakeGoogleKey(scope);
            if (v.field === "privateKey") return privatePem;
            // A complete fake key file, for GOOGLE_APPLICATION_CREDENTIALS-style JSON env vars.
            return JSON.stringify({
              type: "service_account",
              project_id: sa.projectId,
              private_key_id: `cb${fakeApiKey(scope, "").slice(0, 38).toLowerCase()}`,
              private_key: privatePem,
              client_email: sa.clientEmail,
              client_id: "",
              token_uri: sa.tokenUri,
            });
          };
          plain[v.key] = await value();
          redirectFor(r);
        } else if (r.kind === "apns") {
          const ap = config as unknown as { keyId: string; teamId: string };
          if (v.field === "keyId") plain[v.key] = ap.keyId;
          else if (v.field === "teamId") plain[v.key] = ap.teamId;
          else if (v.field === "key") plain[v.key] = fakeApnsKey(scope).privatePem;
          redirectFor(r);
        } else if (r.kind === "oauth" && v.field === "clientSecret") {
          plain[v.key] = fakeApiKey(scope, "cb-");
          for (const hp of config.redirectHosts ?? []) {
            const i = hp.lastIndexOf(":");
            redirects.set(hp, {
              host: hp.slice(0, i),
              port: Number(hp.slice(i + 1)),
              resourceId: r._id.toHexString(),
            });
          }
        } else if (r.kind === "http" && v.field === "key") {
          plain[v.key] = fakeApiKey(scope, config.fakePrefix ?? "cb_");
          for (const hp of config.redirectHosts ?? []) {
            const i = hp.lastIndexOf(":");
            redirects.set(hp, {
              host: hp.slice(0, i),
              port: Number(hp.slice(i + 1)),
              resourceId: r._id.toHexString(),
            });
          }
        }
        break;
      }
    }
  }

  await recordAudit({
    orgId: env.orgId,
    actorId: auth.userId,
    deviceId: auth.deviceId,
    projectId: project._id,
    environmentId: env._id,
    action: "agent.bootstrap",
  });
  return {
    schema: 1,
    version: env.version ?? 1,
    orgId: env.orgId.toHexString(),
    projectId: project._id.toHexString(),
    projectSlug: project.slug,
    environment: env.name,
    envId,
    orgCaCert,
    plain,
    listeners: [...listeners.values()],
    redirects: [...redirects.values()],
    visibleKeys,
  };
}

export async function loadEnvironmentById(envId: Types.ObjectId) {
  return EnvironmentModel.findById(envId).lean();
}
