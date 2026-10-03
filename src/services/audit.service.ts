import type { Types } from "mongoose";
import { logger } from "../logger/logger.js";
import { AuditEventModel } from "../models/audit-event.model.js";
import { UserModel } from "../models/user.model.js";
import { buildPagination, type Pagination } from "../utils/response.js";

export interface AuditInput {
  orgId: Types.ObjectId | string;
  action: string;
  actorId?: Types.ObjectId | string | null;
  deviceId?: Types.ObjectId | string | null;
  projectId?: Types.ObjectId | string | null;
  environmentId?: Types.ObjectId | string | null;
  resourceId?: Types.ObjectId | string | null;
  outcome?: "success" | "denied" | "error";
  target?: string;
  meta?: Record<string, unknown>;
}

/** Trusted audit trail (J8). Never throws into the caller; failures are logged. */
export async function recordAudit(input: AuditInput): Promise<void> {
  try {
    await AuditEventModel.create({ outcome: "success", ...input });
  } catch (err) {
    logger.error(
      `audit: failed to record ${input.action} — ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

export interface AuditEventDto {
  id: string;
  action: string;
  outcome: string;
  actor: { id: string; name: string; email: string } | null;
  target: string | null;
  projectId: string | null;
  environmentId: string | null;
  meta: Record<string, unknown>;
  createdAt: string;
}

export async function listAudit(
  orgId: Types.ObjectId,
  query: { page: number; pageSize: number; action?: string },
): Promise<{ items: AuditEventDto[]; pagination: Pagination }> {
  const filter: Record<string, unknown> = { orgId };
  if (query.action) filter.action = new RegExp(`^${query.action.replace(/[^a-z._]/gi, "")}`);
  const [total, rows] = await Promise.all([
    AuditEventModel.countDocuments(filter),
    AuditEventModel.find(filter)
      .sort({ createdAt: -1 })
      .skip((query.page - 1) * query.pageSize)
      .limit(query.pageSize)
      .lean(),
  ]);
  const actorIds = [
    ...new Set(rows.map((r) => r.actorId?.toHexString()).filter((v): v is string => Boolean(v))),
  ];
  const actors = new Map(
    (await UserModel.find({ _id: { $in: actorIds } }).lean()).map((u) => [u._id.toHexString(), u] as const),
  );
  const items = rows.map((r) => {
    const actor = r.actorId ? actors.get(r.actorId.toHexString()) : undefined;
    return {
      id: r._id.toHexString(),
      action: r.action,
      outcome: r.outcome,
      actor: actor ? { id: actor._id.toHexString(), name: actor.name, email: actor.email } : null,
      target: r.target ?? null,
      projectId: r.projectId?.toHexString() ?? null,
      environmentId: r.environmentId?.toHexString() ?? null,
      meta: (r.meta as Record<string, unknown>) ?? {},
      createdAt: (r.createdAt as Date).toISOString(),
    };
  });
  return { items, pagination: buildPagination({ page: query.page, pageSize: query.pageSize, total }) };
}
