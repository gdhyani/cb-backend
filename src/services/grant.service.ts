import { Types } from "mongoose";
import { z } from "zod";
import { AppError } from "../errors/app-error.js";
import { bus } from "../events/bus.js";
import { logger } from "../logger/logger.js";
import { EnvironmentModel } from "../models/environment.model.js";
import { GrantModel } from "../models/grant.model.js";
import { MembershipModel } from "../models/membership.model.js";
import { ProjectModel } from "../models/project.model.js";
import { UserModel } from "../models/user.model.js";
import { activeGrantFilter, loadEnvironment, loadProject, requireMembership } from "./access.service.js";
import { recordAudit } from "./audit.service.js";
import { listMembers, type MemberDto } from "./org.service.js";
import { assertProfilesExist, DEFAULT_PROFILE } from "./profile.service.js";

const ObjectIdString = z.string().regex(/^[a-f0-9]{24}$/);
const ResourceProfiles = z
  .array(z.object({ resourceId: ObjectIdString, profile: z.string().min(1).max(30) }))
  .max(50);
const FutureDate = z.iso
  .datetime()
  .refine((v) => new Date(v).getTime() > Date.now(), "must be in the future")
  .nullable()
  .optional();

export const CreateGrantBody = z.object({
  userId: z.string(),
  resourceProfiles: ResourceProfiles.optional(),
  expiresAt: FutureDate,
});

export const UpdateGrantBody = z.object({
  resourceProfiles: ResourceProfiles.optional(),
  expiresAt: FutureDate,
});

/** J4: a person's complete access to one project, set in one go. */
export const SetProjectAccessBody = z
  .object({
    /** "project" = every environment, including ones created later; "environments" = only those listed. */
    scope: z.enum(["project", "environments"]),
    environmentIds: z.array(ObjectIdString).max(50).optional(),
    expiresAt: FutureDate,
    resourceProfiles: ResourceProfiles.optional(),
  })
  .refine((b) => b.scope === "project" || (b.environmentIds?.length ?? 0) > 0, {
    message: "choose at least one environment",
    path: ["environmentIds"],
  });

export type GrantScope = "environment" | "project";

export interface GrantDto {
  id: string;
  scope: GrantScope;
  projectId: string;
  /** Null for project grants (they cover every environment). */
  environmentId: string | null;
  userId: string;
  /** Resources not listed use the "default" profile. */
  resourceProfiles: { resourceId: string; profile: string }[];
  expiresAt: string | null;
  createdAt: string;
  createdBy: string;
}

export interface AccessMatrixDto {
  members: MemberDto[];
  environments: { id: string; name: string; killed: boolean }[];
  grants: GrantDto[];
}

type GrantDoc = {
  _id: Types.ObjectId;
  orgId: Types.ObjectId;
  projectId: Types.ObjectId;
  scope?: string | null;
  environmentId?: Types.ObjectId | null;
  userId: Types.ObjectId;
  expiresAt?: Date | null;
  createdAt?: Date;
  createdBy: Types.ObjectId;
  resourceProfiles?: { resourceId?: Types.ObjectId | null; profile?: string | null }[] | null;
};

const scopeOf = (g: Pick<GrantDoc, "scope">): GrantScope =>
  g.scope === "project" ? "project" : "environment";

const toDto = (g: GrantDoc): GrantDto => ({
  id: g._id.toHexString(),
  scope: scopeOf(g),
  projectId: g.projectId.toHexString(),
  environmentId: g.environmentId ? g.environmentId.toHexString() : null,
  userId: g.userId.toHexString(),
  resourceProfiles: (g.resourceProfiles ?? [])
    .filter((p) => p.resourceId && p.profile)
    .map((p) => ({ resourceId: String(p.resourceId), profile: String(p.profile) })),
  expiresAt: g.expiresAt?.toISOString() ?? null,
  createdAt: (g.createdAt ?? new Date()).toISOString(),
  createdBy: g.createdBy.toHexString(),
});

/** Drops "default" entries (the implicit choice) and duplicate resources (last wins). */
function normalizeProfiles(list: { resourceId: string; profile: string }[] | undefined) {
  if (!list) return undefined;
  const byResource = new Map(list.map((p) => [p.resourceId, p.profile] as const));
  return [...byResource]
    .filter(([, profile]) => profile !== DEFAULT_PROFILE)
    .map(([resourceId, profile]) => ({ resourceId, profile }));
}

/** Environments a grant covers (all of the project's for project grants). */
async function environmentsOf(g: Pick<GrantDoc, "scope" | "environmentId" | "projectId">): Promise<string[]> {
  if (scopeOf(g) === "environment") return g.environmentId ? [g.environmentId.toHexString()] : [];
  const envs = await EnvironmentModel.find({ projectId: g.projectId }).select("_id").lean();
  return envs.map((e) => e._id.toHexString());
}

/**
 * Tells agents and tunnels about a grant change. Revocations go through the bus as access.revoked
 * (re-checked against the DB before anything is closed, S3); other changes as config.changed.
 */
async function announce(
  g: GrantDoc,
  change: "created" | "updated" | "revoked" | "profiles",
  reason?: string,
) {
  const userId = g.userId.toHexString();
  if (change === "revoked" || change === "profiles") {
    const why = reason ?? (change === "profiles" ? "credential profile changed" : "access revoked by admin");
    if (scopeOf(g) === "project")
      bus.publish({
        type: "access.revoked",
        scope: "project",
        projectId: g.projectId.toHexString(),
        userId,
        reason: why,
      });
    else
      bus.publish({
        type: "access.revoked",
        scope: "grant",
        environmentId: g.environmentId?.toHexString(),
        userId,
        reason: why,
      });
  }
  if (change !== "revoked")
    for (const environmentId of await environmentsOf(g))
      bus.publish({ type: "config.changed", environmentId });
}

async function emailOf(userId: Types.ObjectId | string) {
  return (await UserModel.findById(userId).lean())?.email ?? String(userId);
}

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

async function assertMember(orgId: Types.ObjectId, userId: string) {
  if (!(await MembershipModel.exists({ orgId, userId })))
    throw new AppError("VALIDATION_FAILED", {
      details: [{ path: "userId", message: "Not a member of this organization." }],
    });
}

/** J4: grant one environment (optionally temporary). Re-granting replaces the previous expiry. */
export async function createGrant(
  actorId: string,
  envId: Types.ObjectId,
  input: z.infer<typeof CreateGrantBody>,
): Promise<GrantDto> {
  const { env } = await loadEnvironment(actorId, envId, "admin");
  await assertMember(env.orgId, input.userId);
  const expiresAt = input.expiresAt ? new Date(input.expiresAt) : null;
  const resourceProfiles = normalizeProfiles(input.resourceProfiles);
  if (resourceProfiles) await assertProfilesExist({ environmentId: envId }, resourceProfiles);
  const existing = await GrantModel.findOne({
    environmentId: envId,
    userId: input.userId,
    ...activeGrantFilter(),
  });
  const grant = existing
    ? Object.assign(
        existing,
        { expiresAt, expiryNotifiedAt: null },
        resourceProfiles ? { resourceProfiles } : {},
      )
    : new GrantModel({
        orgId: env.orgId,
        projectId: env.projectId,
        scope: "environment",
        environmentId: envId,
        userId: input.userId,
        expiresAt,
        resourceProfiles: resourceProfiles ?? [],
        createdBy: actorId,
      });
  await grant.save();
  await announce(grant, existing && resourceProfiles ? "profiles" : "created");
  await recordAudit({
    orgId: env.orgId,
    actorId,
    projectId: env.projectId,
    environmentId: envId,
    action: "grant.created",
    target: await emailOf(input.userId),
    meta: { expiresAt, scope: "environment" },
  });
  return toDto(grant);
}

/**
 * J4: set a person's access to a project exactly — project-wide or a list of environments — with one expiry
 * and one set of credential profiles. Grants no longer wanted are revoked; matching ones are kept (so live
 * connections only drop where access actually changes).
 */
export async function setProjectAccess(
  actorId: string,
  projectId: Types.ObjectId,
  userId: string,
  input: z.infer<typeof SetProjectAccessBody>,
): Promise<GrantDto[]> {
  const { project } = await loadProject(actorId, projectId, "admin");
  await assertMember(project.orgId, userId);
  const membership = await MembershipModel.findOne({ orgId: project.orgId, userId }).lean();
  if (membership && membership.role !== "developer")
    throw new AppError("VALIDATION_FAILED", {
      details: [{ path: "userId", message: "Owners and admins already have access to every project." }],
    });
  const envIds = input.scope === "project" ? [] : [...new Set(input.environmentIds ?? [])];
  if (envIds.length) {
    const found = await EnvironmentModel.countDocuments({ _id: { $in: envIds }, projectId });
    if (found !== envIds.length)
      throw new AppError("VALIDATION_FAILED", {
        details: [{ path: "environmentIds", message: "Every environment must belong to this project." }],
      });
  }
  const resourceProfiles = normalizeProfiles(input.resourceProfiles) ?? [];
  await assertProfilesExist({ projectId }, resourceProfiles);
  const expiresAt = input.expiresAt ? new Date(input.expiresAt) : null;

  const current = await GrantModel.find({ projectId, userId, ...activeGrantFilter() });
  const wanted = (g: (typeof current)[number]) =>
    input.scope === "project"
      ? scopeOf(g) === "project"
      : scopeOf(g) === "environment" && envIds.includes(g.environmentId?.toHexString() ?? "");

  for (const g of current.filter((x) => !wanted(x))) {
    g.revokedAt = new Date();
    g.set("revokedBy", actorId);
    await g.save();
    await announce(g, "revoked", "access changed by admin");
  }

  const targets: { scope: GrantScope; environmentId: Types.ObjectId | null }[] =
    input.scope === "project"
      ? [{ scope: "project", environmentId: null }]
      : envIds.map((id) => ({ scope: "environment", environmentId: new Types.ObjectId(id) }));
  const result: GrantDto[] = [];
  for (const t of targets) {
    const existing = current.find(
      (g) =>
        wanted(g) &&
        (t.scope === "project" || g.environmentId?.toHexString() === t.environmentId?.toHexString()),
    );
    if (existing) {
      const profilesChanged =
        JSON.stringify(toDto(existing).resourceProfiles) !== JSON.stringify(resourceProfiles);
      existing.set({ expiresAt, expiryNotifiedAt: null, resourceProfiles });
      await existing.save();
      await announce(existing, profilesChanged ? "profiles" : "updated");
      result.push(toDto(existing));
      continue;
    }
    const grant = await GrantModel.create({
      orgId: project.orgId,
      projectId,
      scope: t.scope,
      environmentId: t.environmentId,
      userId,
      expiresAt,
      resourceProfiles,
      createdBy: actorId,
    });
    await announce(grant, "created");
    result.push(toDto(grant));
  }
  await recordAudit({
    orgId: project.orgId,
    actorId,
    projectId,
    action: "grant.updated",
    target: await emailOf(userId),
    meta: { scope: input.scope, environments: envIds.length || "all", expiresAt },
  });
  return result;
}

/** J7: remove a person's access to a whole project (every grant), effective within seconds. */
export async function removeProjectAccess(
  actorId: string,
  projectId: Types.ObjectId,
  userId: string,
): Promise<number> {
  const { project } = await loadProject(actorId, projectId, "admin");
  const grants = await GrantModel.find({ projectId, userId, ...activeGrantFilter() });
  for (const g of grants) {
    g.revokedAt = new Date();
    g.set("revokedBy", actorId);
    await g.save();
    await announce(g, "revoked");
  }
  if (grants.length)
    await recordAudit({
      orgId: project.orgId,
      actorId,
      projectId,
      action: "grant.revoked",
      target: await emailOf(userId),
      meta: { grants: grants.length },
    });
  return grants.length;
}

/** J4: change a grant's expiry or credential profiles; live tunnels reconnect when profiles change. */
export async function updateGrant(
  actorId: string,
  grantId: Types.ObjectId,
  input: z.infer<typeof UpdateGrantBody>,
): Promise<GrantDto> {
  const grant = await GrantModel.findById(grantId);
  if (!grant || grant.revokedAt) throw new AppError("NOT_FOUND", { message: "Grant not found." });
  await requireMembership(actorId, grant.orgId, "admin");
  const resourceProfiles = normalizeProfiles(input.resourceProfiles);
  if (resourceProfiles) {
    await assertProfilesExist(
      scopeOf(grant) === "project"
        ? { projectId: grant.projectId }
        : { environmentId: grant.environmentId ?? undefined },
      resourceProfiles,
    );
    grant.set("resourceProfiles", resourceProfiles);
  }
  if (input.expiresAt !== undefined)
    grant.set({ expiresAt: input.expiresAt ? new Date(input.expiresAt) : null, expiryNotifiedAt: null });
  await grant.save();
  await announce(grant, resourceProfiles ? "profiles" : "updated");
  await recordAudit({
    orgId: grant.orgId,
    actorId,
    projectId: grant.projectId,
    environmentId: grant.environmentId ?? undefined,
    action: "grant.updated",
    target: await emailOf(grant.userId),
    meta: { resourceProfiles, expiresAt: input.expiresAt },
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
  await announce(grant, "revoked");
  await recordAudit({
    orgId: grant.orgId,
    actorId,
    projectId: grant.projectId,
    environmentId: grant.environmentId ?? undefined,
    action: "grant.revoked",
    target: await emailOf(grant.userId),
  });
}

export interface MemberAccessDto {
  userId: string;
  projects: {
    projectId: string;
    projectName: string;
    grants: (GrantDto & { environmentName: string | null })[];
  }[];
}

/** Everything one member can reach, grouped by project (for the member detail panel). */
export async function listMemberAccess(
  actorId: string,
  orgId: Types.ObjectId,
  userId: string,
): Promise<MemberAccessDto> {
  await requireMembership(actorId, orgId, "admin");
  const grants = await GrantModel.find({ orgId, userId, ...activeGrantFilter() })
    .sort({ createdAt: 1 })
    .lean();
  const [projects, envs] = await Promise.all([
    ProjectModel.find({ _id: { $in: [...new Set(grants.map((g) => g.projectId))] } })
      .select("name")
      .lean(),
    EnvironmentModel.find({ _id: { $in: grants.map((g) => g.environmentId).filter(Boolean) } })
      .select("name")
      .lean(),
  ]);
  const envName = new Map(envs.map((e) => [e._id.toHexString(), e.name]));
  return {
    userId,
    projects: projects.map((p) => ({
      projectId: p._id.toHexString(),
      projectName: p.name,
      grants: grants
        .filter((g) => g.projectId.equals(p._id))
        .map((g) => ({
          ...toDto(g),
          environmentName: g.environmentId ? (envName.get(g.environmentId.toHexString()) ?? null) : null,
        })),
    })),
  };
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
    await announce(grant, "revoked", "temporary access expired");
    await recordAudit({
      orgId: grant.orgId,
      projectId: grant.projectId,
      environmentId: grant.environmentId ?? undefined,
      action: "grant.expired",
      target: grant.userId.toHexString(),
    });
  }
  if (expired.length > 0) logger.info(`grants: ${expired.length} temporary grant(s) expired`);
  return expired.length;
}
