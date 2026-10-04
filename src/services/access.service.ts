import type { Types } from "mongoose";
import { AppError } from "../errors/app-error.js";
import { EnvironmentModel } from "../models/environment.model.js";
import { GrantModel } from "../models/grant.model.js";
import { KillSwitchModel } from "../models/kill-switch.model.js";
import { MembershipModel, type Role } from "../models/membership.model.js";
import { ProjectModel } from "../models/project.model.js";

const RANK: Record<Role, number> = { developer: 1, admin: 2, owner: 3 };

export function isAdminRole(role: Role): boolean {
  return RANK[role] >= RANK.admin;
}

export async function requireMembership(userId: string, orgId: Types.ObjectId, minRole: Role = "developer") {
  const membership = await MembershipModel.findOne({ orgId, userId }).lean();
  if (!membership) throw new AppError("NOT_FOUND", { message: "Organization not found." });
  if (RANK[membership.role as Role] < RANK[minRole]) {
    throw new AppError("FORBIDDEN", { message: `This action needs the ${minRole} role or higher.` });
  }
  return membership;
}

export async function loadProject(userId: string, projectId: Types.ObjectId, minRole: Role = "developer") {
  const project = await ProjectModel.findById(projectId).lean();
  if (!project) throw new AppError("NOT_FOUND", { message: "Project not found." });
  const membership = await requireMembership(userId, project.orgId, minRole);
  return { project, membership };
}

export async function loadEnvironment(userId: string, envId: Types.ObjectId, minRole: Role = "developer") {
  const env = await EnvironmentModel.findById(envId).lean();
  if (!env) throw new AppError("NOT_FOUND", { message: "Environment not found." });
  const membership = await requireMembership(userId, env.orgId, minRole);
  return { env, membership };
}

/** Active = not revoked and not expired. */
export function activeGrantFilter(now = new Date()) {
  return { revokedAt: null, $or: [{ expiresAt: null }, { expiresAt: { $gt: now } }] };
}

/** Active grants that give access to this environment: its own grants or a project-wide grant. */
export function coveringGrantFilter(
  env: { _id: Types.ObjectId; projectId: Types.ObjectId },
  now = new Date(),
): Record<string, unknown> {
  return {
    $and: [
      activeGrantFilter(now),
      { $or: [{ environmentId: env._id }, { scope: "project", projectId: env.projectId }] },
    ],
  };
}

/** M0-D1: owners/admins have implicit access; developers need an environment or project grant. */
export async function hasEnvironmentAccess(
  userId: string,
  env: { _id: Types.ObjectId; orgId: Types.ObjectId; projectId: Types.ObjectId },
) {
  const membership = await MembershipModel.findOne({ orgId: env.orgId, userId }).lean();
  if (!membership) return false;
  if (isAdminRole(membership.role as Role)) return true;
  return Boolean(await GrantModel.exists({ userId, ...coveringGrantFilter(env) }));
}

/** Active kill switches that stop this user/device/environment (and resource, for tunnels). */
async function activeKillSwitch(
  userId: string,
  env: { _id: Types.ObjectId; orgId: Types.ObjectId },
  extra: { deviceId?: string; resourceId?: string },
) {
  const targets: Record<string, unknown>[] = [
    { scope: "org" },
    { scope: "environment", targetId: env._id },
    { scope: "user", targetId: userId },
  ];
  if (extra.deviceId) targets.push({ scope: "device", targetId: extra.deviceId });
  if (extra.resourceId) targets.push({ scope: "resource", targetId: extra.resourceId });
  return KillSwitchModel.findOne({ orgId: env.orgId, clearedAt: null, $or: targets }).lean();
}

/** Runtime check for bootstrap and tunnels: environment suspension, kill switches, then access. */
export async function assertRuntimeAccess(
  userId: string,
  env: { _id: Types.ObjectId; orgId: Types.ObjectId; projectId: Types.ObjectId; killedAt?: Date | null },
  extra: { deviceId?: string; resourceId?: string } = {},
) {
  if (env.killedAt) throw new AppError("ENVIRONMENT_KILLED");
  const kill = await activeKillSwitch(userId, env, extra);
  if (kill)
    throw new AppError("KILLSWITCH_ACTIVE", {
      message: `Access is stopped by an emergency stop: ${kill.reason}`,
    });
  if (!(await hasEnvironmentAccess(userId, env))) throw new AppError("NO_ACCESS");
}
