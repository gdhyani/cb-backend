import type { Types } from "mongoose";
import { AppError } from "../errors/app-error.js";
import { MembershipModel } from "../models/membership.model.js";
import { UserModel } from "../models/user.model.js";
import { WebSessionModel } from "../models/web-session.model.js";
import { isAdminRole, requireMembership } from "./access.service.js";
import { recordAudit } from "./audit.service.js";

export interface SessionDto {
  id: string;
  user: { id: string; name: string; email: string };
  userAgent: string;
  createdAt: string;
  lastSeenAt: string | null;
  expiresAt: string;
  /** The session making this request. */
  current: boolean;
}

/** Active dashboard sessions of the org's members (admins). */
export async function listOrgSessions(
  actorId: string,
  actorSessionId: string | undefined,
  orgId: Types.ObjectId,
): Promise<SessionDto[]> {
  await requireMembership(actorId, orgId, "admin");
  const userIds = (await MembershipModel.find({ orgId }).lean()).map((m) => m.userId);
  const [sessions, users] = await Promise.all([
    WebSessionModel.find({ userId: { $in: userIds }, revokedAt: null, expiresAt: { $gt: new Date() } })
      .sort({ lastSeenAt: -1, createdAt: -1 })
      .lean(),
    UserModel.find({ _id: { $in: userIds } })
      .select("name email")
      .lean(),
  ]);
  const byId = new Map(users.map((u) => [u._id.toHexString(), u]));
  return sessions.map((s) => {
    const u = byId.get(s.userId.toHexString());
    return {
      id: s._id.toHexString(),
      user: { id: s.userId.toHexString(), name: u?.name ?? "", email: u?.email ?? "" },
      userAgent: s.userAgent ?? "",
      createdAt: (s.createdAt ?? new Date()).toISOString(),
      lastSeenAt: s.lastSeenAt?.toISOString() ?? null,
      expiresAt: s.expiresAt.toISOString(),
      current: s._id.toHexString() === actorSessionId,
    };
  });
}

/** Signs a dashboard session out: your own, or a member's if you administer an org they belong to. */
export async function revokeSession(actorId: string, sessionId: Types.ObjectId): Promise<void> {
  const session = await WebSessionModel.findById(sessionId);
  if (!session || session.revokedAt) throw new AppError("NOT_FOUND", { message: "Session not found." });
  const ownerOrgs = await MembershipModel.find({ userId: session.userId }).lean();
  if (session.userId.toHexString() !== actorId) {
    const adminOf = await MembershipModel.find({
      userId: actorId,
      orgId: { $in: ownerOrgs.map((m) => m.orgId) },
    }).lean();
    if (!adminOf.some((m) => isAdminRole(m.role as "owner" | "admin" | "developer")))
      throw new AppError("NOT_FOUND", { message: "Session not found." });
  }
  session.revokedAt = new Date();
  await session.save();
  const email = (await UserModel.findById(session.userId).select("email").lean())?.email ?? "";
  for (const m of ownerOrgs)
    await recordAudit({ orgId: m.orgId, actorId, action: "session.revoked", target: email });
}
