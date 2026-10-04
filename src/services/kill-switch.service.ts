import type { Types } from "mongoose";
import { z } from "zod";
import { AppError } from "../errors/app-error.js";
import { bus } from "../events/bus.js";
import { DeviceModel } from "../models/device.model.js";
import { EnvironmentModel } from "../models/environment.model.js";
import { KILL_SWITCH_SCOPES, KillSwitchModel, type KillSwitchScope } from "../models/kill-switch.model.js";
import { MembershipModel } from "../models/membership.model.js";
import { ProjectModel } from "../models/project.model.js";
import { ResourceModel } from "../models/resource.model.js";
import { UserModel } from "../models/user.model.js";
import { requireMembership } from "./access.service.js";
import { recordAudit } from "./audit.service.js";

export const ActivateKillSwitchBody = z
  .object({
    scope: z.enum(KILL_SWITCH_SCOPES),
    targetId: z
      .string()
      .regex(/^[a-f0-9]{24}$/)
      .optional(),
    /** FR-UI-002: a typed reason is required. */
    reason: z.string().trim().min(3).max(300),
  })
  .refine((b) => b.scope === "org" || Boolean(b.targetId), {
    message: "choose what to stop",
    path: ["targetId"],
  });

export interface KillSwitchDto {
  id: string;
  scope: KillSwitchScope;
  targetId: string | null;
  targetLabel: string;
  reason: string;
  createdBy: string;
  createdAt: string;
  clearedAt: string | null;
}

type KillSwitchDoc = {
  _id: Types.ObjectId;
  scope: string;
  targetId?: Types.ObjectId | null;
  targetLabel?: string | null;
  reason: string;
  createdBy: Types.ObjectId;
  createdAt?: Date;
  clearedAt?: Date | null;
};

const toDto = (k: KillSwitchDoc): KillSwitchDto => ({
  id: k._id.toHexString(),
  scope: k.scope as KillSwitchScope,
  targetId: k.targetId ? k.targetId.toHexString() : null,
  targetLabel: k.targetLabel ?? "",
  reason: k.reason,
  createdBy: k.createdBy.toHexString(),
  createdAt: (k.createdAt ?? new Date()).toISOString(),
  clearedAt: k.clearedAt?.toISOString() ?? null,
});

/** Confirms the target belongs to this org and returns a human label for lists and audit. */
async function resolveTarget(
  orgId: Types.ObjectId,
  scope: KillSwitchScope,
  targetId?: string,
): Promise<string> {
  const notInOrg = () =>
    new AppError("VALIDATION_FAILED", {
      details: [{ path: "targetId", message: "Not found in this organization." }],
    });
  switch (scope) {
    case "org":
      return "Entire organization";
    case "environment": {
      const env = await EnvironmentModel.findOne({ _id: targetId, orgId }).lean();
      if (!env) throw notInOrg();
      const project = await ProjectModel.findById(env.projectId).select("name").lean();
      return `${project?.name ?? "Project"} / ${env.name}`;
    }
    case "resource": {
      const r = await ResourceModel.findOne({ _id: targetId, orgId }).lean();
      if (!r) throw notInOrg();
      return `${r.name} (${r.kind})`;
    }
    case "user": {
      if (!(await MembershipModel.exists({ orgId, userId: targetId }))) throw notInOrg();
      return (await UserModel.findById(targetId).select("email").lean())?.email ?? String(targetId);
    }
    case "device": {
      const d = await DeviceModel.findById(targetId).lean();
      if (!d || !(await MembershipModel.exists({ orgId, userId: d.userId }))) throw notInOrg();
      return d.name;
    }
  }
}

/** Every environment of the org gets config.changed so agents re-check (restores access after a clear). */
async function announceOrgConfigChange(orgId: Types.ObjectId) {
  for (const env of await EnvironmentModel.find({ orgId }).select("_id").lean())
    bus.publish({ type: "config.changed", environmentId: env._id.toHexString() });
}

export async function listKillSwitches(actorId: string, orgId: Types.ObjectId): Promise<KillSwitchDto[]> {
  await requireMembership(actorId, orgId, "admin");
  const rows = await KillSwitchModel.find({ orgId }).sort({ clearedAt: 1, createdAt: -1 }).limit(100).lean();
  return rows.map(toDto);
}

/** J7: stop access now at the chosen scope; affected tunnels close within seconds (FR-GW-007). */
export async function activateKillSwitch(
  actorId: string,
  orgId: Types.ObjectId,
  input: z.infer<typeof ActivateKillSwitchBody>,
): Promise<KillSwitchDto> {
  await requireMembership(actorId, orgId, "admin");
  const targetLabel = await resolveTarget(orgId, input.scope, input.targetId);
  const existing = await KillSwitchModel.findOne({
    orgId,
    scope: input.scope,
    targetId: input.targetId ?? null,
    clearedAt: null,
  }).lean();
  if (existing)
    throw new AppError("CONFLICT", { message: `A kill switch is already active for ${targetLabel}.` });
  const kill = await KillSwitchModel.create({
    orgId,
    scope: input.scope,
    targetId: input.targetId ?? null,
    targetLabel,
    reason: input.reason,
    createdBy: actorId,
  });
  const reason = `kill switch: ${input.reason}`;
  const id = input.targetId;
  const event =
    input.scope === "org"
      ? { scope: "org" as const, orgId: orgId.toHexString() }
      : input.scope === "environment"
        ? { scope: "environment" as const, environmentId: id }
        : input.scope === "resource"
          ? { scope: "resource" as const, resourceId: id }
          : input.scope === "user"
            ? { scope: "membership" as const, orgId: orgId.toHexString(), userId: id }
            : { scope: "device" as const, deviceId: id };
  bus.publish({ type: "access.revoked", reason, ...event });
  await recordAudit({
    orgId,
    actorId,
    action: "killswitch.activated",
    target: targetLabel,
    meta: { scope: input.scope, reason: input.reason },
  });
  return toDto(kill);
}

export async function clearKillSwitch(actorId: string, killSwitchId: Types.ObjectId): Promise<KillSwitchDto> {
  const kill = await KillSwitchModel.findById(killSwitchId);
  if (!kill || kill.clearedAt) throw new AppError("NOT_FOUND", { message: "Kill switch not found." });
  await requireMembership(actorId, kill.orgId, "admin");
  kill.clearedAt = new Date();
  kill.set("clearedBy", actorId);
  await kill.save();
  await announceOrgConfigChange(kill.orgId);
  await recordAudit({
    orgId: kill.orgId,
    actorId,
    action: "killswitch.cleared",
    target: kill.targetLabel,
    meta: { scope: kill.scope },
  });
  return toDto(kill);
}
