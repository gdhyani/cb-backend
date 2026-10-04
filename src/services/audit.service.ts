import type { Types } from "mongoose";
import { logger } from "../logger/logger.js";
import { AuditEventModel } from "../models/audit-event.model.js";
import { EnvironmentModel } from "../models/environment.model.js";
import { ProjectModel } from "../models/project.model.js";
import { ResourceModel } from "../models/resource.model.js";
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

export const AUDIT_CATEGORIES = ["team", "access", "config", "security", "runtime"] as const;
export type AuditCategory = (typeof AUDIT_CATEGORIES)[number];

const CATEGORY_PATTERNS: Record<AuditCategory, RegExp> = {
  team: /^(org|member)\./,
  access: /^(grant\.|environment\.(killed|revived))/,
  config: /^(project\.|resource\.|profile\.|variable\.|environment\.(created|renamed|deleted))/,
  security: /^device\./,
  runtime: /^(agent|tunnel|http)\./,
};

export function categoryOf(action: string): AuditCategory {
  return (
    (Object.keys(CATEGORY_PATTERNS) as AuditCategory[]).find((c) => CATEGORY_PATTERNS[c].test(action)) ??
    "config"
  );
}

interface NamedRef {
  id: string;
  name: string;
}

export interface AuditEventDto {
  id: string;
  action: string;
  category: AuditCategory;
  outcome: string;
  actor: { id: string; name: string; email: string } | null;
  /** Free text target (email, name) or, when it is a user id, the resolved user. */
  target: string | null;
  targetUser: NamedRef | null;
  project: NamedRef | null;
  environment: NamedRef | null;
  resource: (NamedRef & { kind: string }) | null;
  meta: Record<string, unknown>;
  createdAt: string;
}

const OBJECT_ID = /^[a-f0-9]{24}$/;
const ids = (values: (Types.ObjectId | string | null | undefined)[]) => [
  ...new Set(values.map((v) => (v ? String(v) : "")).filter((v) => OBJECT_ID.test(v))),
];

export async function listAudit(
  orgId: Types.ObjectId,
  query: { page: number; pageSize: number; action?: string; category?: AuditCategory },
): Promise<{ items: AuditEventDto[]; pagination: Pagination }> {
  const filter: Record<string, unknown> = { orgId };
  if (query.category) filter.action = CATEGORY_PATTERNS[query.category];
  else if (query.action) filter.action = new RegExp(`^${query.action.replace(/[^a-z._]/gi, "")}`);
  const [total, rows] = await Promise.all([
    AuditEventModel.countDocuments(filter),
    AuditEventModel.find(filter)
      .sort({ createdAt: -1 })
      .skip((query.page - 1) * query.pageSize)
      .limit(query.pageSize)
      .lean(),
  ]);
  // Resolve every referenced id in one query per collection.
  const [users, projects, envs, resources] = await Promise.all([
    UserModel.find({
      _id: { $in: ids([...rows.map((r) => r.actorId), ...rows.map((r) => r.target)]) },
    }).lean(),
    ProjectModel.find({ _id: { $in: ids(rows.map((r) => r.projectId)) } }).lean(),
    EnvironmentModel.find({ _id: { $in: ids(rows.map((r) => r.environmentId)) } }).lean(),
    ResourceModel.find({ _id: { $in: ids(rows.map((r) => r.resourceId)) } }).lean(),
  ]);
  const byId = <T extends { _id: Types.ObjectId }>(list: T[]) =>
    new Map(list.map((x) => [x._id.toHexString(), x] as const));
  const userMap = byId(users);
  const projectMap = byId(projects);
  const envMap = byId(envs);
  const resourceMap = byId(resources);
  const ref = (id: Types.ObjectId | null | undefined, map: Map<string, { name: string }>) => {
    const hit = id ? map.get(id.toHexString()) : undefined;
    return id && hit ? { id: id.toHexString(), name: hit.name } : null;
  };

  const items = rows.map((r): AuditEventDto => {
    const actor = r.actorId ? userMap.get(r.actorId.toHexString()) : undefined;
    const targetUser = r.target && OBJECT_ID.test(r.target) ? userMap.get(r.target) : undefined;
    const resource = r.resourceId ? resourceMap.get(r.resourceId.toHexString()) : undefined;
    return {
      id: r._id.toHexString(),
      action: r.action,
      category: categoryOf(r.action),
      outcome: r.outcome,
      actor: actor ? { id: actor._id.toHexString(), name: actor.name, email: actor.email } : null,
      target: targetUser ? null : (r.target ?? null),
      targetUser: targetUser ? { id: targetUser._id.toHexString(), name: targetUser.name } : null,
      project: ref(r.projectId, projectMap),
      environment: ref(r.environmentId, envMap),
      resource:
        resource && r.resourceId
          ? { id: r.resourceId.toHexString(), name: resource.name, kind: resource.kind }
          : null,
      meta: (r.meta as Record<string, unknown>) ?? {},
      createdAt: (r.createdAt as Date).toISOString(),
    };
  });
  return { items, pagination: buildPagination({ page: query.page, pageSize: query.pageSize, total }) };
}
