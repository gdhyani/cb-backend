import type { Types } from "mongoose";
import { z } from "zod";
import { getEnv } from "../config/env.js";
import { hashToken, newToken, newUserCode } from "../crypto/tokens.js";
import { AppError } from "../errors/app-error.js";
import { bus } from "../events/bus.js";
import { DEVICE_TOKEN_PREFIX } from "../middlewares/auth.middleware.js";
import { DeviceModel } from "../models/device.model.js";
import { DeviceCodeModel } from "../models/device-code.model.js";
import { MembershipModel } from "../models/membership.model.js";
import { UserModel } from "../models/user.model.js";
import { isAdminRole, requireMembership } from "./access.service.js";
import { recordAudit } from "./audit.service.js";

const CODE_TTL_MS = 10 * 60_000;
const DEVICE_TTL_MS = 30 * 86_400_000;
const POLL_INTERVAL_SEC = 2;

export const StartDeviceBody = z.object({
  deviceName: z.string().trim().min(1).max(100),
  os: z.string().trim().max(40).default("unknown"),
});
export const ApproveDeviceBody = z.object({
  userCode: z
    .string()
    .trim()
    .toUpperCase()
    .regex(/^[A-Z2-9]{4}-[A-Z2-9]{4}$/, "looks like ABCD-EFGH"),
  deviceName: z.string().trim().min(1).max(100).optional(),
});
export const PollDeviceBody = z.object({ deviceCode: z.string().min(10) });

export interface DeviceDto {
  id: string;
  name: string;
  os: string;
  user: { id: string; name: string; email: string };
  lastSeenAt: string | null;
  createdAt: string;
  revoked: boolean;
  /** From the agent heartbeat; online = reported within the last 3 minutes. */
  agent: { online: boolean; version: string | null; activeTunnels: number; seenAt: string | null };
}

export const AGENT_ONLINE_MS = 3 * 60_000;

export const HeartbeatBody = z.object({
  version: z.string().max(40),
  activeTunnels: z.number().int().min(0).max(100_000),
});

/** FR-AGT: the agent reports in about once a minute. */
export async function recordHeartbeat(
  deviceId: string,
  input: z.infer<typeof HeartbeatBody>,
): Promise<{ ok: true }> {
  await DeviceModel.updateOne(
    { _id: deviceId, revokedAt: null },
    { agentVersion: input.version, agentSeenAt: new Date(), activeTunnels: input.activeTunnels },
  );
  return { ok: true };
}

/** FR-AUTH-002 step 1: the CLI asks for a code. */
export async function startDeviceAuth(input: z.infer<typeof StartDeviceBody>) {
  const deviceCode = newToken("cbdc_");
  const userCode = newUserCode();
  await DeviceCodeModel.create({
    userCode,
    deviceCodeHash: hashToken(deviceCode),
    deviceName: input.deviceName,
    os: input.os,
    expiresAt: new Date(Date.now() + CODE_TTL_MS),
  });
  return {
    deviceCode,
    userCode,
    verificationUrl: `${getEnv().DASHBOARD_URL}/device?code=${userCode}`,
    interval: POLL_INTERVAL_SEC,
    expiresIn: CODE_TTL_MS / 1000,
  };
}

/** Step 2: a logged-in user approves the code in the dashboard. */
export async function approveDeviceAuth(userId: string, input: z.infer<typeof ApproveDeviceBody>) {
  const code = await DeviceCodeModel.findOne({
    userCode: input.userCode,
    consumedAt: null,
    expiresAt: { $gt: new Date() },
  });
  if (!code)
    throw new AppError("NOT_FOUND", {
      message: 'That code is invalid or expired. Run "npx cb login" again.',
    });
  if (code.approvedBy) throw new AppError("CONFLICT", { message: "This code was already approved." });
  code.set("approvedBy", userId);
  code.approvedAt = new Date();
  if (input.deviceName) code.deviceName = input.deviceName;
  await code.save();
  return { deviceName: code.deviceName, os: code.os };
}

/** Step 3: the CLI polls; on approval it receives its device token exactly once. */
export async function pollDeviceToken(input: z.infer<typeof PollDeviceBody>) {
  const code = await DeviceCodeModel.findOne({ deviceCodeHash: hashToken(input.deviceCode) });
  if (!code || code.consumedAt)
    throw new AppError("NOT_FOUND", { message: 'Unknown login request. Run "npx cb login" again.' });
  if (code.expiresAt.getTime() <= Date.now()) throw new AppError("DEVICE_CODE_EXPIRED");
  if (!code.approvedBy) throw new AppError("DEVICE_AUTH_PENDING");
  const token = newToken(DEVICE_TOKEN_PREFIX);
  const device = await DeviceModel.create({
    userId: code.approvedBy,
    name: code.deviceName,
    os: code.os,
    tokenHash: hashToken(token),
    expiresAt: new Date(Date.now() + DEVICE_TTL_MS),
    lastSeenAt: new Date(),
  });
  code.consumedAt = new Date();
  code.set("deviceId", device._id);
  await code.save();
  const user = await UserModel.findById(code.approvedBy).lean();
  for (const m of await MembershipModel.find({ userId: code.approvedBy }).lean()) {
    await recordAudit({
      orgId: m.orgId,
      actorId: code.approvedBy,
      deviceId: device._id,
      action: "device.approved",
      target: device.name,
    });
  }
  return {
    token,
    device: { id: device._id.toHexString(), name: device.name },
    user: { id: code.approvedBy.toHexString(), name: user?.name ?? "", email: user?.email ?? "" },
  };
}

async function toDtos(
  devices: {
    _id: Types.ObjectId;
    userId: Types.ObjectId;
    name: string;
    os?: string | null;
    lastSeenAt?: Date | null;
    createdAt?: Date;
    revokedAt?: Date | null;
    agentVersion?: string | null;
    agentSeenAt?: Date | null;
    activeTunnels?: number | null;
  }[],
): Promise<DeviceDto[]> {
  const users = new Map(
    (await UserModel.find({ _id: { $in: devices.map((d) => d.userId) } }).lean()).map(
      (u) => [u._id.toHexString(), u] as const,
    ),
  );
  return devices.map((d) => {
    const u = users.get(d.userId.toHexString());
    return {
      id: d._id.toHexString(),
      name: d.name,
      os: d.os ?? "unknown",
      user: { id: d.userId.toHexString(), name: u?.name ?? "", email: u?.email ?? "" },
      lastSeenAt: d.lastSeenAt?.toISOString() ?? null,
      createdAt: (d.createdAt ?? new Date()).toISOString(),
      revoked: Boolean(d.revokedAt),
      agent: {
        online: Boolean(d.agentSeenAt && Date.now() - d.agentSeenAt.getTime() < AGENT_ONLINE_MS),
        version: d.agentVersion ?? null,
        activeTunnels: d.activeTunnels ?? 0,
        seenAt: d.agentSeenAt?.toISOString() ?? null,
      },
    };
  });
}

export async function listMyDevices(userId: string): Promise<DeviceDto[]> {
  return toDtos(await DeviceModel.find({ userId, revokedAt: null }).sort({ lastSeenAt: -1 }).lean());
}

export async function listOrgDevices(actorId: string, orgId: Types.ObjectId): Promise<DeviceDto[]> {
  await requireMembership(actorId, orgId, "admin");
  const userIds = (await MembershipModel.find({ orgId }).lean()).map((m) => m.userId);
  return toDtos(
    await DeviceModel.find({ userId: { $in: userIds }, revokedAt: null })
      .sort({ lastSeenAt: -1 })
      .lean(),
  );
}

/** Owners revoke their own devices; admins revoke devices of members in their orgs. */
export async function revokeDevice(actorId: string, deviceId: Types.ObjectId): Promise<void> {
  const device = await DeviceModel.findById(deviceId);
  if (!device || device.revokedAt) throw new AppError("NOT_FOUND", { message: "Device not found." });
  const ownerId = device.userId.toHexString();
  const sharedOrgs = await MembershipModel.find({ userId: device.userId }).lean();
  if (ownerId !== actorId) {
    const adminOf = await MembershipModel.find({
      userId: actorId,
      orgId: { $in: sharedOrgs.map((m) => m.orgId) },
    }).lean();
    if (!adminOf.some((m) => isAdminRole(m.role as "owner" | "admin" | "developer"))) {
      throw new AppError("NOT_FOUND", { message: "Device not found." });
    }
  }
  device.revokedAt = new Date();
  await device.save();
  bus.publish({
    type: "access.revoked",
    scope: "device",
    deviceId: deviceId.toHexString(),
    userId: ownerId,
    reason: "device revoked",
  });
  for (const m of sharedOrgs) {
    await recordAudit({ orgId: m.orgId, actorId, deviceId, action: "device.revoked", target: device.name });
  }
}
