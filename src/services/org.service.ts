import type { Types } from "mongoose";
import { z } from "zod";
import { AppError } from "../errors/app-error.js";
import { bus } from "../events/bus.js";
import { GrantModel } from "../models/grant.model.js";
import { MembershipModel, ROLES, type Role } from "../models/membership.model.js";
import { OrganizationModel } from "../models/organization.model.js";
import { UserModel } from "../models/user.model.js";
import { requireMembership } from "./access.service.js";
import { recordAudit } from "./audit.service.js";

export const UpdateRoleBody = z.object({ role: z.enum(ROLES) });

export interface OrgDto {
  id: string;
  name: string;
  role: Role;
  memberCount: number;
}

export interface MemberDto {
  userId: string;
  name: string;
  email: string;
  role: Role;
  joinedAt: string;
}

export async function listMyOrgs(userId: string): Promise<OrgDto[]> {
  const memberships = await MembershipModel.find({ userId }).lean();
  const orgIds = memberships.map((m) => m.orgId);
  const [orgs, counts] = await Promise.all([
    OrganizationModel.find({ _id: { $in: orgIds } }).lean(),
    MembershipModel.aggregate<{ _id: Types.ObjectId; n: number }>([
      { $match: { orgId: { $in: orgIds } } },
      { $group: { _id: "$orgId", n: { $sum: 1 } } },
    ]),
  ]);
  const countOf = new Map(counts.map((c) => [c._id.toHexString(), c.n] as const));
  return orgs.map((o) => ({
    id: o._id.toHexString(),
    name: o.name,
    role: memberships.find((m) => m.orgId.equals(o._id))?.role as Role,
    memberCount: countOf.get(o._id.toHexString()) ?? 0,
  }));
}

export async function getOrg(userId: string, orgId: Types.ObjectId): Promise<OrgDto> {
  const membership = await requireMembership(userId, orgId);
  const org = await OrganizationModel.findById(orgId).lean();
  if (!org) throw new AppError("NOT_FOUND", { message: "Organization not found." });
  return {
    id: org._id.toHexString(),
    name: org.name,
    role: membership.role as Role,
    memberCount: await MembershipModel.countDocuments({ orgId }),
  };
}

export async function listMembers(userId: string, orgId: Types.ObjectId): Promise<MemberDto[]> {
  await requireMembership(userId, orgId);
  const memberships = await MembershipModel.find({ orgId }).sort({ createdAt: 1 }).lean();
  const users = new Map(
    (await UserModel.find({ _id: { $in: memberships.map((m) => m.userId) } }).lean()).map(
      (u) => [u._id.toHexString(), u] as const,
    ),
  );
  return memberships.map((m) => {
    const u = users.get(m.userId.toHexString());
    return {
      userId: m.userId.toHexString(),
      name: u?.name ?? "",
      email: u?.email ?? "",
      role: m.role as Role,
      joinedAt: (m.createdAt as Date).toISOString(),
    };
  });
}

async function assertNotLastOwner(orgId: Types.ObjectId, targetUserId: Types.ObjectId): Promise<void> {
  const target = await MembershipModel.findOne({ orgId, userId: targetUserId }).lean();
  if (target?.role !== "owner") return;
  if ((await MembershipModel.countDocuments({ orgId, role: "owner" })) <= 1) throw new AppError("LAST_OWNER");
}

export async function updateMemberRole(
  actorId: string,
  orgId: Types.ObjectId,
  targetUserId: Types.ObjectId,
  role: Role,
): Promise<MemberDto> {
  const actor = await requireMembership(actorId, orgId, "admin");
  const target = await MembershipModel.findOne({ orgId, userId: targetUserId });
  if (!target) throw new AppError("NOT_FOUND", { message: "Member not found." });
  if ((role === "owner" || target.role === "owner") && actor.role !== "owner") {
    throw new AppError("FORBIDDEN", { message: "Only owners can grant or remove the owner role." });
  }
  if (target.role === "owner" && role !== "owner") await assertNotLastOwner(orgId, targetUserId);
  const previous = target.role;
  target.role = role;
  await target.save();
  if (previous !== "developer" && role === "developer") {
    // Lost implicit admin access: live tunnels without a grant must close.
    bus.publish({
      type: "access.revoked",
      scope: "membership",
      orgId: orgId.toHexString(),
      userId: targetUserId.toHexString(),
      reason: "role changed",
    });
  }
  await recordAudit({
    orgId,
    actorId,
    action: "member.role_changed",
    target: targetUserId.toHexString(),
    meta: { from: previous, to: role },
  });
  const member = (await listMembers(actorId, orgId)).find((m) => m.userId === targetUserId.toHexString());
  if (!member) throw new AppError("NOT_FOUND", { message: "Member not found." });
  return member;
}

export async function removeMember(
  actorId: string,
  orgId: Types.ObjectId,
  targetUserId: Types.ObjectId,
): Promise<void> {
  const isSelf = targetUserId.toHexString() === actorId;
  await requireMembership(actorId, orgId, isSelf ? "developer" : "admin");
  const target = await MembershipModel.findOne({ orgId, userId: targetUserId }).lean();
  if (!target) throw new AppError("NOT_FOUND", { message: "Member not found." });
  await assertNotLastOwner(orgId, targetUserId);
  await MembershipModel.deleteOne({ _id: target._id });
  await GrantModel.updateMany(
    { orgId, userId: targetUserId, revokedAt: null },
    { revokedAt: new Date(), revokedBy: actorId },
  );
  bus.publish({
    type: "access.revoked",
    scope: "membership",
    orgId: orgId.toHexString(),
    userId: targetUserId.toHexString(),
    reason: "removed from organization",
  });
  await recordAudit({ orgId, actorId, action: "member.removed", target: targetUserId.toHexString() });
}
