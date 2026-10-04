import type { Types } from "mongoose";
import { AppError } from "../errors/app-error.js";
import { EnvironmentModel } from "../models/environment.model.js";
import { GrantModel } from "../models/grant.model.js";
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

/** M0-D1: owners/admins have implicit access; developers need an active grant on the environment. */
export async function hasEnvironmentAccess(
  userId: string,
  env: { _id: Types.ObjectId; orgId: Types.ObjectId },
) {
  const membership = await MembershipModel.findOne({ orgId: env.orgId, userId }).lean();
  if (!membership) return false;
  if (isAdminRole(membership.role as Role)) return true;
  return Boolean(await GrantModel.exists({ environmentId: env._id, userId, ...activeGrantFilter() }));
}

/** Runtime check for bootstrap and tunnels: membership, kill switch, then access. */
export async function assertRuntimeAccess(
  userId: string,
  env: { _id: Types.ObjectId; orgId: Types.ObjectId; killedAt?: Date | null },
) {
  if (env.killedAt) throw new AppError("ENVIRONMENT_KILLED");
  if (!(await hasEnvironmentAccess(userId, env))) throw new AppError("NO_ACCESS");
}
