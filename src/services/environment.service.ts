import type { Types } from "mongoose";
import { z } from "zod";
import { AppError } from "../errors/app-error.js";
import { bus } from "../events/bus.js";
import { EnvironmentModel } from "../models/environment.model.js";
import { GrantModel } from "../models/grant.model.js";
import { VariableModel } from "../models/variable.model.js";
import { hasEnvironmentAccess, loadEnvironment, loadProject } from "./access.service.js";
import { recordAudit } from "./audit.service.js";
import { EnvName } from "./project.service.js";

export const CreateEnvironmentBody = z.object({ name: EnvName });
export const UpdateEnvironmentBody = z.object({
  name: EnvName.optional(),
  killed: z.boolean().optional(),
  reason: z.string().trim().min(3, "give a reason of at least 3 characters").max(200).optional(),
});

export interface EnvironmentDto {
  id: string;
  projectId: string;
  orgId: string;
  name: string;
  killed: boolean;
  killedReason: string | null;
  version: number;
  hasAccess: boolean;
}

async function toDto(
  userId: string,
  env: {
    _id: Types.ObjectId;
    projectId: Types.ObjectId;
    orgId: Types.ObjectId;
    name: string;
    killedAt?: Date | null;
    killedReason?: string | null;
    version?: number | null;
  },
): Promise<EnvironmentDto> {
  return {
    id: env._id.toHexString(),
    projectId: env.projectId.toHexString(),
    orgId: env.orgId.toHexString(),
    name: env.name,
    killed: Boolean(env.killedAt),
    killedReason: env.killedReason ?? null,
    version: env.version ?? 1,
    hasAccess: await hasEnvironmentAccess(userId, env),
  };
}

/** Any change that alters what a developer's snapshot contains (FR-EVT-001 config.changed). */
export async function touchEnvironment(environmentId: Types.ObjectId): Promise<void> {
  await EnvironmentModel.updateOne({ _id: environmentId }, { $inc: { version: 1 } });
  bus.publish({ type: "config.changed", environmentId: environmentId.toHexString() });
}

export async function listEnvironments(userId: string, projectId: Types.ObjectId): Promise<EnvironmentDto[]> {
  await loadProject(userId, projectId);
  const envs = await EnvironmentModel.find({ projectId }).sort({ createdAt: 1 }).lean();
  return Promise.all(envs.map((e) => toDto(userId, e)));
}

export async function getEnvironment(userId: string, envId: Types.ObjectId): Promise<EnvironmentDto> {
  const { env } = await loadEnvironment(userId, envId);
  return toDto(userId, env);
}

export async function createEnvironment(
  actorId: string,
  projectId: Types.ObjectId,
  input: z.infer<typeof CreateEnvironmentBody>,
): Promise<EnvironmentDto> {
  const { project } = await loadProject(actorId, projectId, "admin");
  if (await EnvironmentModel.exists({ projectId, name: input.name })) {
    throw new AppError("CONFLICT", { message: `Environment "${input.name}" already exists.` });
  }
  const env = await EnvironmentModel.create({ orgId: project.orgId, projectId, name: input.name });
  await recordAudit({
    orgId: project.orgId,
    actorId,
    projectId,
    environmentId: env._id,
    action: "environment.created",
    target: env.name,
  });
  return toDto(actorId, env);
}

/** Rename, or kill / revive (J7 kill switch at environment scope). */
export async function updateEnvironment(
  actorId: string,
  envId: Types.ObjectId,
  input: z.infer<typeof UpdateEnvironmentBody>,
): Promise<EnvironmentDto> {
  const { env } = await loadEnvironment(actorId, envId, "admin");
  const update: Record<string, unknown> = {};
  if (input.name && input.name !== env.name) {
    if (await EnvironmentModel.exists({ projectId: env.projectId, name: input.name })) {
      throw new AppError("CONFLICT", { message: `Environment "${input.name}" already exists.` });
    }
    update.name = input.name;
  }
  if (input.killed === true && !env.killedAt) {
    if (!input.reason) {
      throw new AppError("VALIDATION_FAILED", {
        details: [{ path: "reason", message: "A reason is required to disable an environment." }],
      });
    }
    Object.assign(update, { killedAt: new Date(), killedReason: input.reason });
  }
  if (input.killed === false && env.killedAt) Object.assign(update, { killedAt: null, killedReason: null });
  const updated = await EnvironmentModel.findByIdAndUpdate(
    envId,
    { ...update, $inc: { version: 1 } },
    { returnDocument: "after" },
  ).lean();
  if (!updated) throw new AppError("NOT_FOUND", { message: "Environment not found." });
  if (input.killed === true && !env.killedAt) {
    bus.publish({
      type: "access.revoked",
      scope: "environment",
      environmentId: envId.toHexString(),
      reason: input.reason ?? "environment disabled",
    });
    await recordAudit({
      orgId: env.orgId,
      actorId,
      projectId: env.projectId,
      environmentId: envId,
      action: "environment.killed",
      meta: { reason: input.reason },
    });
  } else if (input.killed === false && env.killedAt) {
    bus.publish({ type: "config.changed", environmentId: envId.toHexString() });
    await recordAudit({
      orgId: env.orgId,
      actorId,
      projectId: env.projectId,
      environmentId: envId,
      action: "environment.revived",
    });
  } else if (update.name) {
    bus.publish({ type: "config.changed", environmentId: envId.toHexString() });
    await recordAudit({
      orgId: env.orgId,
      actorId,
      projectId: env.projectId,
      environmentId: envId,
      action: "environment.renamed",
      target: input.name,
    });
  }
  return toDto(actorId, updated);
}

export async function deleteEnvironment(actorId: string, envId: Types.ObjectId): Promise<void> {
  const { env } = await loadEnvironment(actorId, envId, "admin");
  // Loaded lazily: resource.service depends on this module (load-order cycle).
  const { purgeResources } = await import("./resource.service.js");
  await Promise.all([
    VariableModel.deleteMany({ environmentId: envId }),
    purgeResources({ environmentId: envId }),
    GrantModel.updateMany(
      { environmentId: envId, revokedAt: null },
      { revokedAt: new Date(), revokedBy: actorId },
    ),
  ]);
  await EnvironmentModel.deleteOne({ _id: envId });
  bus.publish({
    type: "access.revoked",
    scope: "environment",
    environmentId: envId.toHexString(),
    reason: "environment deleted",
  });
  await recordAudit({
    orgId: env.orgId,
    actorId,
    projectId: env.projectId,
    action: "environment.deleted",
    target: env.name,
  });
}
