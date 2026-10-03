import type { Types } from "mongoose";
import type { BusEvent } from "../events/bus.js";
import { DeviceModel } from "../models/device.model.js";
import { EnvironmentModel } from "../models/environment.model.js";
import { assertRuntimeAccess } from "./access.service.js";

export interface RuntimeSubject {
  userId: string;
  deviceId: string;
  environmentId: string;
  projectId: string;
  orgId: string;
}

/** Could this access.revoked event concern the subject? (cheap pre-filter before re-checking) */
export function eventConcerns(
  event: Extract<BusEvent, { type: "access.revoked" }>,
  s: RuntimeSubject,
): boolean {
  switch (event.scope) {
    case "grant":
      return event.environmentId === s.environmentId && event.userId === s.userId;
    case "device":
      return event.deviceId === s.deviceId;
    case "membership":
      return event.orgId === s.orgId && event.userId === s.userId;
    case "environment":
      return event.environmentId === s.environmentId;
    case "project":
      return event.projectId === s.projectId;
  }
}

/** Re-evaluates access from the database (S3). Returns a reason when access is gone. */
export async function revalidate(s: RuntimeSubject): Promise<string | undefined> {
  const device = await DeviceModel.findOne({
    _id: s.deviceId,
    revokedAt: null,
    expiresAt: { $gt: new Date() },
  }).lean();
  if (!device) return "device revoked";
  const env = await EnvironmentModel.findById(s.environmentId as unknown as Types.ObjectId).lean();
  if (!env) return "environment deleted";
  try {
    await assertRuntimeAccess(s.userId, env);
    return undefined;
  } catch (err) {
    return err instanceof Error ? err.message : "access revoked";
  }
}
