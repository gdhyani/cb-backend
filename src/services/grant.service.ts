import type { Types } from "mongoose";
import { z } from "zod";
import { AppError } from "../errors/app-error.js";
import { bus } from "../events/bus.js";
import { logger } from "../logger/logger.js";
import { EnvironmentModel } from "../models/environment.model.js";
import { GrantModel } from "../models/grant.model.js";
import { MembershipModel } from "../models/membership.model.js";
import { UserModel } from "../models/user.model.js";
import { activeGrantFilter, loadEnvironment, loadProject, requireMembership } from "./access.service.js";
import { recordAudit } from "./audit.service.js";
import { listMembers, type MemberDto } from "./org.service.js";

export const CreateGrantBody = z.object({
  userId: z.string(),
  expiresAt: z.iso
    .datetime()
    .refine((v) => new Date(v).getTime() > Date.now(), "must be in the future")
    .nullable()
    .optional(),
});

export interface GrantDto {
  id: string;
  environmentId: string;
  userId: string;
  expiresAt: string | null;
  createdAt: string;
  createdBy: string;
}

export interface AccessMatrixDto {
  members: MemberDto[];
  environments: { id: string; name: string; killed: boolean }[];
  grants: GrantDto[];
}

const toDto = (g: {
  _id: Types.ObjectId;
  environmentId: Types.ObjectId;
  userId: Types.ObjectId;
  expiresAt?: Date | null;
  createdAt?: Date;
  createdBy: Types.ObjectId;
}): GrantDto => ({
  id: g._id.toHexString(),
  environmentId: g.environmentId.toHexString(),
  userId: g.userId.toHexString(),
  expiresAt: g.expiresAt?.toISOString() ?? null,
  createdAt: (g.createdAt ?? new Date()).toISOString(),
  createdBy: g.createdBy.toHexString(),
});

/** Members × environments with active grants (owners/admins have implicit access). */
export async function getAccessMatrix(actorId: string, projectId: Types.ObjectId): Promise<AccessMatrixDto> {
  const { project } = await loadProject(actorId, projectId, "admin");
  const [members, envs, grants] = await Promise.all([
    listMembers(actorId, project.orgId),
    EnvironmentModel.find({ projectId }).sort({ createdAt: 1 }).lean(),
    GrantModel.find({ projectId, ...activeGrantFilter() }).lean(),
  ]);
  return {
    members,
    environments: envs.map((e) => ({ id: e._id.toHexString(), name: e.name, killed: Boolean(e.killedAt) })),
    grants: grants.map(toDto),
  };
}

/** J4: grant access (optionally temporary). Re-granting replaces the previous active grant's expiry. */
export async function createGrant(
  actorId: string,
  envId: Types.ObjectId,
  input: z.infer<typeof CreateGrantBody>,
): Promise<GrantDto> {
  const { env } = await loadEnvironment(actorId, envId, "admin");
  if (!(await MembershipModel.exists({ orgId: env.orgId, userId: input.userId }))) {
    throw new AppError("VALIDATION_FAILED", {
      details: [{ path: "userId", message: "Not a member of this organization." }],
    });
  }
  const expiresAt = input.expiresAt ? new Date(input.expiresAt) : null;
  const existing = await GrantModel.findOne({
    environmentId: envId,
    userId: input.userId,
    ...activeGrantFilter(),
  });
  const grant = existing
    ? Object.assign(existing, { expiresAt, expiryNotifiedAt: null })
    : new GrantModel({
        orgId: env.orgId,
        projectId: env.projectId,
        environmentId: envId,
        userId: input.userId,
        expiresAt,
        createdBy: actorId,
      });
  await grant.save();
  bus.publish({ type: "config.changed", environmentId: envId.toHexString() });
  const user = await UserModel.findById(input.userId).lean();
  await recordAudit({
    orgId: env.orgId,
    actorId,
    projectId: env.projectId,
    environmentId: envId,
    action: "grant.created",
    target: user?.email ?? input.userId,
    meta: { expiresAt },
  });
  return toDto(grant);
}

/** J7: revoke now; live tunnels close via the bus (FR-GW-007). */
export async function revokeGrant(actorId: string, grantId: Types.ObjectId): Promise<void> {
  const grant = await GrantModel.findById(grantId);
  if (!grant || grant.revokedAt) throw new AppError("NOT_FOUND", { message: "Grant not found." });
  await requireMembership(actorId, grant.orgId, "admin");
  grant.revokedAt = new Date();
  grant.set("revokedBy", actorId);
  await grant.save();
  bus.publish({
    type: "access.revoked",
    scope: "grant",
    environmentId: grant.environmentId.toHexString(),
    userId: grant.userId.toHexString(),
    reason: "access revoked by admin",
  });
  const user = await UserModel.findById(grant.userId).lean();
  await recordAudit({
    orgId: grant.orgId,
    actorId,
    projectId: grant.projectId,
    environmentId: grant.environmentId,
    action: "grant.revoked",
    target: user?.email ?? grant.userId.toHexString(),
  });
}

/** Announces expired temporary grants once so tunnels close and agents stop (runs on an interval). */
export async function sweepExpiredGrants(now = new Date()): Promise<number> {
  const expired = await GrantModel.find({
    revokedAt: null,
    expiryNotifiedAt: null,
    expiresAt: { $ne: null, $lte: now },
  }).lean();
  for (const grant of expired) {
    await GrantModel.updateOne({ _id: grant._id }, { expiryNotifiedAt: now });
    bus.publish({
      type: "access.revoked",
      scope: "grant",
      environmentId: grant.environmentId.toHexString(),
      userId: grant.userId.toHexString(),
      reason: "temporary access expired",
    });
    await recordAudit({
      orgId: grant.orgId,
      projectId: grant.projectId,
      environmentId: grant.environmentId,
      action: "grant.expired",
      target: grant.userId.toHexString(),
    });
  }
  if (expired.length > 0) logger.info(`grants: ${expired.length} temporary grant(s) expired`);
  return expired.length;
}
