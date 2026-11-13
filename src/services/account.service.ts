import { verify } from "@node-rs/argon2";
import type { Types } from "mongoose";
import { z } from "zod";
import { AppError } from "../errors/app-error.js";
import { bus } from "../events/bus.js";
import { logger } from "../logger/logger.js";
import { AuditEventModel } from "../models/audit-event.model.js";
import { CredentialProfileModel } from "../models/credential-profile.model.js";
import { DeviceModel } from "../models/device.model.js";
import { DeviceCodeModel } from "../models/device-code.model.js";
import { EnvironmentModel } from "../models/environment.model.js";
import { FakeKeyModel } from "../models/fake-key.model.js";
import { GrantModel } from "../models/grant.model.js";
import { InviteModel } from "../models/invite.model.js";
import { KillSwitchModel } from "../models/kill-switch.model.js";
import { MembershipModel, type Role } from "../models/membership.model.js";
import { OrgCaModel } from "../models/org-ca.model.js";
import { OrganizationModel } from "../models/organization.model.js";
import { ProjectModel } from "../models/project.model.js";
import { RefreshTokenModel } from "../models/refresh-token.model.js";
import { ResourceModel } from "../models/resource.model.js";
import { TokenSwapModel } from "../models/token-swap.model.js";
import { UserModel } from "../models/user.model.js";
import { VariableModel } from "../models/variable.model.js";
import { WebSessionModel } from "../models/web-session.model.js";
import { WebhookDeliveryModel } from "../models/webhook-delivery.model.js";
import { WebhookEventModel } from "../models/webhook-event.model.js";
import { WebhookListenerModel } from "../models/webhook-listener.model.js";
import { WebhookOwnerModel } from "../models/webhook-owner.model.js";
import { requireMembership } from "./access.service.js";
import { recordAudit } from "./audit.service.js";

/** FR-ACC-001 / FR-ACC-002: both deletions re-check the password and a typed confirmation. */
export const DeleteConfirmBody = z.object({
  password: z.string().min(1),
  confirm: z.string(),
});
export type DeleteConfirmInput = z.infer<typeof DeleteConfirmBody>;

export interface DeletionPreviewDto {
  email: string;
  /** Organizations where this user is the only owner: deleting the account deletes them too. */
  orgsDeleted: { id: string; name: string; memberCount: number }[];
  /** Organizations the user simply leaves. */
  orgsLeft: { id: string; name: string; role: Role }[];
}

export async function verifyPassword(userId: string, password: string): Promise<void> {
  const user = await UserModel.findById(userId).select("+passwordHash");
  if (!user) throw new AppError("UNAUTHORIZED");
  if (!(await verify(user.passwordHash, password))) throw new AppError("WRONG_PASSWORD");
}

/**
 * Hard-deletes an organization and everything in it (no auth check — callers verify).
 * Live tunnels are told first so they close; provider-side webhooks are removed best effort.
 */
export async function purgeOrganization(actorId: string, orgId: Types.ObjectId): Promise<void> {
  bus.publish({
    type: "access.revoked",
    scope: "org",
    orgId: orgId.toHexString(),
    reason: "organization deleted",
  });
  const webhooks = await ResourceModel.find({ orgId, kind: "webhook" }).lean();
  if (webhooks.length > 0) {
    const { disconnectWebhook } = await import("./webhook-setup.service.js");
    for (const resource of webhooks) {
      try {
        await disconnectWebhook(resource);
      } catch (err) {
        logger.warn(
          `account: could not disconnect webhook ${resource.name} — ${err instanceof Error ? err.message : String(err)}`,
        );
      }
    }
  }
  const envIds = (await EnvironmentModel.find({ orgId }).select("_id").lean()).map((e) => e._id);
  const { purgeResources } = await import("./resource.service.js");
  await VariableModel.deleteMany({ orgId });
  await purgeResources({ orgId });
  await Promise.all([
    WebhookEventModel.deleteMany({ $or: [{ orgId }, { environmentId: { $in: envIds } }] }),
    WebhookDeliveryModel.deleteMany({ environmentId: { $in: envIds } }),
    WebhookOwnerModel.deleteMany({ environmentId: { $in: envIds } }),
    WebhookListenerModel.deleteMany({ environmentId: { $in: envIds } }),
    GrantModel.deleteMany({ orgId }),
    InviteModel.deleteMany({ orgId }),
    KillSwitchModel.deleteMany({ orgId }),
    CredentialProfileModel.deleteMany({ orgId }),
    OrgCaModel.deleteMany({ orgId }),
  ]);
  await EnvironmentModel.deleteMany({ orgId });
  await ProjectModel.deleteMany({ orgId });
  await AuditEventModel.deleteMany({ orgId });
  await MembershipModel.deleteMany({ orgId });
  await OrganizationModel.deleteOne({ _id: orgId });
  // The organization's own audit log is gone, so this line is the only trace.
  logger.info(`account: organization ${orgId.toHexString()} deleted by user ${actorId}`);
}

/** Splits the user's organizations by whether they are the only owner. */
async function classifyMemberships(userId: string) {
  const memberships = await MembershipModel.find({ userId }).lean();
  return Promise.all(
    memberships.map(async (m) => {
      const soleOwner =
        m.role === "owner" && (await MembershipModel.countDocuments({ orgId: m.orgId, role: "owner" })) <= 1;
      return { membership: m, soleOwner };
    }),
  );
}

export async function deletionPreview(userId: string): Promise<DeletionPreviewDto> {
  const user = await UserModel.findById(userId).lean();
  if (!user) throw new AppError("UNAUTHORIZED");
  const rows = await classifyMemberships(userId);
  const orgs = new Map(
    (await OrganizationModel.find({ _id: { $in: rows.map((r) => r.membership.orgId) } }).lean()).map(
      (o) => [o._id.toHexString(), o.name] as const,
    ),
  );
  const preview: DeletionPreviewDto = { email: user.email, orgsDeleted: [], orgsLeft: [] };
  for (const { membership: m, soleOwner } of rows) {
    const id = m.orgId.toHexString();
    const name = orgs.get(id) ?? "";
    if (soleOwner) {
      preview.orgsDeleted.push({
        id,
        name,
        memberCount: await MembershipModel.countDocuments({ orgId: m.orgId }),
      });
    } else {
      preview.orgsLeft.push({ id, name, role: m.role as Role });
    }
  }
  return preview;
}

export async function deleteAccount(userId: string, input: DeleteConfirmInput): Promise<void> {
  await verifyPassword(userId, input.password);
  const user = await UserModel.findById(userId).lean();
  if (!user) throw new AppError("UNAUTHORIZED");
  if (input.confirm.trim().toLowerCase() !== user.email.trim().toLowerCase()) {
    throw new AppError("CONFIRMATION_MISMATCH");
  }

  for (const { membership: m, soleOwner } of await classifyMemberships(userId)) {
    if (soleOwner) {
      await purgeOrganization(userId, m.orgId);
      continue;
    }
    await MembershipModel.deleteOne({ _id: m._id });
    await GrantModel.deleteMany({ orgId: m.orgId, userId: user._id });
    bus.publish({
      type: "access.revoked",
      scope: "membership",
      orgId: m.orgId.toHexString(),
      userId,
      reason: "account deleted",
    });
    await recordAudit({ orgId: m.orgId, actorId: userId, action: "member.removed", target: userId });
  }

  const devices = await DeviceModel.find({ userId: user._id }).select("_id").lean();
  const deviceIds = devices.map((d) => d._id);
  for (const id of deviceIds) {
    bus.publish({
      type: "access.revoked",
      scope: "device",
      deviceId: id.toHexString(),
      userId,
      reason: "account deleted",
    });
  }
  await Promise.all([
    RefreshTokenModel.deleteMany({ deviceId: { $in: deviceIds } }),
    FakeKeyModel.deleteMany({ deviceId: { $in: deviceIds } }),
    TokenSwapModel.deleteMany({ deviceId: { $in: deviceIds } }),
    WebSessionModel.deleteMany({ userId: user._id }),
    DeviceCodeModel.deleteMany({ approvedBy: user._id }),
    WebhookDeliveryModel.deleteMany({ $or: [{ userId: user._id }, { deviceId: { $in: deviceIds } }] }),
    WebhookListenerModel.deleteMany({ $or: [{ userId: user._id }, { deviceId: { $in: deviceIds } }] }),
    WebhookOwnerModel.deleteMany({ $or: [{ userId: user._id }, { deviceId: { $in: deviceIds } }] }),
  ]);
  // A departed person leaves no live invite links behind, and stops aimed at them (or their laptops) have nothing
  // left to stop.
  await Promise.all([
    InviteModel.updateMany({ createdBy: user._id, usedAt: null, revokedAt: null }, { revokedAt: new Date() }),
    KillSwitchModel.deleteMany({
      $or: [
        { scope: "user", targetId: user._id },
        { scope: "device", targetId: { $in: deviceIds } },
      ],
    }),
  ]);
  await DeviceModel.deleteMany({ _id: { $in: deviceIds } });
  await UserModel.deleteOne({ _id: user._id });
  logger.info(`account: user ${userId} deleted their account`);
}

export async function deleteOrganization(
  actorId: string,
  orgId: Types.ObjectId,
  input: DeleteConfirmInput,
): Promise<void> {
  await requireMembership(actorId, orgId, "owner");
  await verifyPassword(actorId, input.password);
  const org = await OrganizationModel.findById(orgId).lean();
  if (!org) throw new AppError("NOT_FOUND", { message: "Organization not found." });
  if (input.confirm.trim() !== org.name.trim()) throw new AppError("CONFIRMATION_MISMATCH");
  await purgeOrganization(actorId, orgId);
}
