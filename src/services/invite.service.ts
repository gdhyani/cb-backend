import type { Types } from "mongoose";
import { z } from "zod";
import { getEnv } from "../config/env.js";
import { hashToken, newToken } from "../crypto/tokens.js";
import { AppError } from "../errors/app-error.js";
import { InviteModel } from "../models/invite.model.js";
import { MembershipModel, ROLES, type Role } from "../models/membership.model.js";
import { OrganizationModel } from "../models/organization.model.js";
import { requireMembership } from "./access.service.js";
import { recordAudit } from "./audit.service.js";
import { createUser } from "./auth.service.js";

const INVITE_TTL_MS = 7 * 86_400_000;

export const CreateInviteBody = z.object({
  role: z.enum(ROLES).default("developer"),
  email: z.email().optional(),
});
export const AcceptInviteBody = z.object({
  token: z.string().min(10),
  name: z.string().trim().min(1).max(100).optional(),
  email: z.email().optional(),
  password: z.string().min(8, "must be at least 8 characters").max(200).optional(),
});

export interface InviteDto {
  id: string;
  role: Role;
  email: string | null;
  expiresAt: string;
  createdAt: string;
}

const toDto = (i: {
  _id: Types.ObjectId;
  role: string;
  email?: string | null;
  expiresAt: Date;
  createdAt?: Date;
}): InviteDto => ({
  id: i._id.toHexString(),
  role: i.role as Role,
  email: i.email ?? null,
  expiresAt: i.expiresAt.toISOString(),
  createdAt: (i.createdAt ?? new Date()).toISOString(),
});

/** J4: the admin copies the link (no email sending in M0). */
export async function createInvite(
  actorId: string,
  orgId: Types.ObjectId,
  input: z.infer<typeof CreateInviteBody>,
) {
  const actor = await requireMembership(actorId, orgId, "admin");
  if (input.role === "owner" && actor.role !== "owner") {
    throw new AppError("FORBIDDEN", { message: "Only owners can invite owners." });
  }
  const token = newToken("cbi_");
  const invite = await InviteModel.create({
    orgId,
    role: input.role,
    email: input.email ?? null,
    tokenHash: hashToken(token),
    createdBy: actorId,
    expiresAt: new Date(Date.now() + INVITE_TTL_MS),
  });
  await recordAudit({ orgId, actorId, action: "member.invited", target: input.email ?? input.role });
  return { ...toDto(invite), token, url: `${getEnv().DASHBOARD_URL}/invite/${token}` };
}

export async function listInvites(actorId: string, orgId: Types.ObjectId): Promise<InviteDto[]> {
  await requireMembership(actorId, orgId, "admin");
  const invites = await InviteModel.find({
    orgId,
    usedAt: null,
    revokedAt: null,
    expiresAt: { $gt: new Date() },
  })
    .sort({ createdAt: -1 })
    .lean();
  return invites.map(toDto);
}

export async function revokeInvite(
  actorId: string,
  orgId: Types.ObjectId,
  inviteId: Types.ObjectId,
): Promise<void> {
  await requireMembership(actorId, orgId, "admin");
  const res = await InviteModel.updateOne({ _id: inviteId, orgId, usedAt: null }, { revokedAt: new Date() });
  if (res.matchedCount === 0) throw new AppError("NOT_FOUND", { message: "Invite not found." });
}

async function findUsableInvite(token: string) {
  const invite = await InviteModel.findOne({
    tokenHash: hashToken(token),
    usedAt: null,
    revokedAt: null,
    expiresAt: { $gt: new Date() },
  });
  if (!invite) throw new AppError("INVITE_INVALID");
  return invite;
}

export async function previewInvite(token: string) {
  const invite = await findUsableInvite(token);
  const org = await OrganizationModel.findById(invite.orgId).lean();
  return {
    orgName: org?.name ?? "",
    role: invite.role as Role,
    email: invite.email ?? null,
    expiresAt: invite.expiresAt.toISOString(),
  };
}

/** Logged-in users join directly; new users are created from name/email/password. */
export async function acceptInvite(
  input: z.infer<typeof AcceptInviteBody>,
  currentUserId?: string,
): Promise<{ userId: string; orgId: string; created: boolean }> {
  const invite = await findUsableInvite(input.token);
  let userId = currentUserId;
  let created = false;
  if (!userId) {
    if (!input.name || !input.email || !input.password) {
      throw new AppError("VALIDATION_FAILED", {
        message: "Name, email and password are required to create your account.",
      });
    }
    if (invite.email && invite.email !== input.email.toLowerCase()) {
      throw new AppError("FORBIDDEN", { message: "This invite was issued for a different email address." });
    }
    const user = await createUser({ name: input.name, email: input.email, password: input.password });
    userId = user._id.toHexString();
    created = true;
  }
  if (!(await MembershipModel.exists({ orgId: invite.orgId, userId }))) {
    await MembershipModel.create({ orgId: invite.orgId, userId, role: invite.role });
  }
  invite.usedAt = new Date();
  invite.set("usedBy", userId);
  await invite.save();
  await recordAudit({
    orgId: invite.orgId,
    actorId: userId,
    action: "member.joined",
    meta: { role: invite.role },
  });
  return { userId, orgId: invite.orgId.toHexString(), created };
}
