import { Types } from "mongoose";
import { AuditEventModel } from "../models/audit-event.model.js";
import { GrantModel } from "../models/grant.model.js";
import { ProjectModel } from "../models/project.model.js";
import { ResourceModel } from "../models/resource.model.js";
import { activeGrantFilter, isAdminRole, requireMembership } from "./access.service.js";
import { AUDIT_CATEGORIES, type AuditCategory, categoryOf } from "./audit.service.js";

export const STATS_DAYS = 14;

export interface OrgStatsDto {
  /** "org" for owners/admins; "me" for developers, who only see their own activity. */
  scope: "org" | "me";
  days: { date: string; connections: number; denied: number; byCategory: Record<AuditCategory, number> }[];
  connectionsByProject: { projectId: string; name: string; connections: number; daily: number[] }[];
  resourcesByKind: { kind: string; count: number }[];
  grants: { permanent: number; temporary: number };
}

const dayKey = (d: Date) => d.toISOString().slice(0, 10);

/** Dashboard charts: daily activity, connections per project, resource mix and grant mix (last 14 days). */
export async function getOrgStats(userId: string, orgId: Types.ObjectId): Promise<OrgStatsDto> {
  const membership = await requireMembership(userId, orgId);
  const scope = isAdminRole(membership.role) ? "org" : "me";
  const since = new Date();
  since.setUTCHours(0, 0, 0, 0);
  since.setUTCDate(since.getUTCDate() - (STATS_DAYS - 1));
  const keys = Array.from({ length: STATS_DAYS }, (_, i) =>
    dayKey(new Date(since.getTime() + i * 86_400_000)),
  );
  const actorFilter = scope === "me" ? { actorId: new Types.ObjectId(userId) } : {};

  const [byDayAction, byProject, kinds, grants, projects] = await Promise.all([
    AuditEventModel.aggregate<{ _id: { day: string; action: string; outcome: string }; n: number }>([
      { $match: { orgId, createdAt: { $gte: since }, ...actorFilter } },
      {
        $group: {
          _id: {
            day: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
            action: "$action",
            outcome: "$outcome",
          },
          n: { $sum: 1 },
        },
      },
    ]),
    AuditEventModel.aggregate<{ _id: { day: string; projectId: Types.ObjectId }; n: number }>([
      { $match: { orgId, action: "tunnel.opened", createdAt: { $gte: since }, ...actorFilter } },
      {
        $group: {
          _id: {
            day: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
            projectId: "$projectId",
          },
          n: { $sum: 1 },
        },
      },
    ]),
    ResourceModel.aggregate<{ _id: string; n: number }>([
      { $match: { orgId, disabledAt: null } },
      { $group: { _id: "$kind", n: { $sum: 1 } } },
      { $sort: { n: -1 } },
    ]),
    GrantModel.find({ orgId, ...activeGrantFilter(), ...(scope === "me" ? { userId } : {}) })
      .select("expiresAt")
      .lean(),
    ProjectModel.find({ orgId }).select("name").lean(),
  ]);

  const emptyCategories = () =>
    Object.fromEntries(AUDIT_CATEGORIES.map((c) => [c, 0])) as Record<AuditCategory, number>;
  const days = keys.map((date) => ({ date, connections: 0, denied: 0, byCategory: emptyCategories() }));
  const index = new Map(keys.map((k, i) => [k, i]));
  for (const row of byDayAction) {
    const day = days[index.get(row._id.day) ?? -1];
    if (!day) continue;
    day.byCategory[categoryOf(row._id.action)] += row.n;
    if (row._id.action === "tunnel.opened") day.connections += row.n;
    if (row._id.outcome === "denied") day.denied += row.n;
  }

  const names = new Map(projects.map((p) => [p._id.toHexString(), p.name]));
  const perProject = new Map<string, number[]>();
  for (const row of byProject) {
    const id = row._id.projectId?.toHexString();
    const i = index.get(row._id.day);
    if (!id || i === undefined || !names.has(id)) continue;
    const daily = perProject.get(id) ?? Array<number>(STATS_DAYS).fill(0);
    daily[i] = (daily[i] ?? 0) + row.n;
    perProject.set(id, daily);
  }
  const connectionsByProject = [...names]
    .map(([projectId, name]) => {
      const daily = perProject.get(projectId) ?? Array<number>(STATS_DAYS).fill(0);
      return { projectId, name, daily, connections: daily.reduce((a, b) => a + b, 0) };
    })
    .sort((a, b) => b.connections - a.connections);

  return {
    scope,
    days,
    connectionsByProject,
    resourcesByKind: kinds.map((k) => ({ kind: k._id, count: k.n })),
    grants: {
      permanent: grants.filter((g) => !g.expiresAt).length,
      temporary: grants.filter((g) => g.expiresAt).length,
    },
  };
}
