import type { Types } from "mongoose";
import { z } from "zod";
import { AppError } from "../errors/app-error.js";
import { bus } from "../events/bus.js";
import { EnvironmentModel } from "../models/environment.model.js";
import { GrantModel } from "../models/grant.model.js";
import { ProjectModel } from "../models/project.model.js";
import { VariableModel } from "../models/variable.model.js";
import { hasEnvironmentAccess, loadProject, requireMembership } from "./access.service.js";
import { recordAudit } from "./audit.service.js";

export const EnvName = z
  .string()
  .trim()
  .toLowerCase()
  .regex(/^[a-z][a-z0-9-]{0,30}$/, "use lowercase letters, digits and dashes");

export const CreateProjectBody = z.object({
  name: z.string().trim().min(1).max(80),
  description: z.string().trim().max(500).optional(),
  environments: z.array(EnvName).min(1).max(10).default(["development", "staging"]),
});
export const UpdateProjectBody = z.object({
  name: z.string().trim().min(1).max(80).optional(),
  description: z.string().trim().max(500).optional(),
});

export interface EnvironmentSummaryDto {
  id: string;
  name: string;
  killed: boolean;
  killedReason: string | null;
  hasAccess: boolean;
}

export interface ProjectDto {
  id: string;
  orgId: string;
  name: string;
  slug: string;
  description: string;
  environments: EnvironmentSummaryDto[];
  createdAt: string;
}

export function slugify(name: string): string {
  return (
    name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 60) || "project"
  );
}

async function toDto(
  userId: string,
  project: {
    _id: Types.ObjectId;
    orgId: Types.ObjectId;
    name: string;
    slug: string;
    description?: string | null;
    createdAt?: Date;
  },
): Promise<ProjectDto> {
  const envs = await EnvironmentModel.find({ projectId: project._id }).sort({ createdAt: 1 }).lean();
  return {
    id: project._id.toHexString(),
    orgId: project.orgId.toHexString(),
    name: project.name,
    slug: project.slug,
    description: project.description ?? "",
    createdAt: (project.createdAt ?? new Date()).toISOString(),
    environments: await Promise.all(
      envs.map(async (e) => ({
        id: e._id.toHexString(),
        name: e.name,
        killed: Boolean(e.killedAt),
        killedReason: e.killedReason ?? null,
        hasAccess: await hasEnvironmentAccess(userId, e),
      })),
    ),
  };
}

/** Every member sees the project list (developers read-only, FR-UI-004). */
export async function listProjects(userId: string, orgId: Types.ObjectId): Promise<ProjectDto[]> {
  await requireMembership(userId, orgId);
  const projects = await ProjectModel.find({ orgId }).sort({ createdAt: 1 }).lean();
  return Promise.all(projects.map((p) => toDto(userId, p)));
}

export async function createProject(
  actorId: string,
  orgId: Types.ObjectId,
  input: z.infer<typeof CreateProjectBody>,
): Promise<ProjectDto> {
  await requireMembership(actorId, orgId, "admin");
  const slug = slugify(input.name);
  if (await ProjectModel.exists({ orgId, slug })) {
    throw new AppError("CONFLICT", { message: `A project named "${input.name}" already exists.` });
  }
  const project = await ProjectModel.create({
    orgId,
    name: input.name,
    slug,
    description: input.description ?? "",
  });
  await EnvironmentModel.insertMany(
    [...new Set(input.environments)].map((name) => ({ orgId, projectId: project._id, name })),
  );
  await recordAudit({
    orgId,
    actorId,
    projectId: project._id,
    action: "project.created",
    target: project.name,
  });
  return toDto(actorId, project);
}

export async function getProject(userId: string, projectId: Types.ObjectId): Promise<ProjectDto> {
  const { project } = await loadProject(userId, projectId);
  return toDto(userId, project);
}

/** Finds a project by id or slug inside an org (used by the CLI). */
export async function findProject(
  userId: string,
  orgId: Types.ObjectId,
  idOrSlug: string,
): Promise<ProjectDto> {
  await requireMembership(userId, orgId);
  const project = await ProjectModel.findOne({
    orgId,
    ...(/^[a-f0-9]{24}$/.test(idOrSlug) ? { _id: idOrSlug } : { slug: idOrSlug.toLowerCase() }),
  }).lean();
  if (!project) throw new AppError("NOT_FOUND", { message: `Project "${idOrSlug}" not found.` });
  return toDto(userId, project);
}

export async function updateProject(
  actorId: string,
  projectId: Types.ObjectId,
  input: z.infer<typeof UpdateProjectBody>,
): Promise<ProjectDto> {
  const { project } = await loadProject(actorId, projectId, "admin");
  const update: Record<string, string> = {};
  if (input.name) update.name = input.name;
  if (input.description !== undefined) update.description = input.description;
  const updated = await ProjectModel.findByIdAndUpdate(project._id, update, {
    returnDocument: "after",
  }).lean();
  if (!updated) throw new AppError("NOT_FOUND", { message: "Project not found." });
  await recordAudit({
    orgId: project.orgId,
    actorId,
    projectId,
    action: "project.updated",
    target: updated.name,
  });
  return toDto(actorId, updated);
}

export async function deleteProject(actorId: string, projectId: Types.ObjectId): Promise<void> {
  const { project } = await loadProject(actorId, projectId, "admin");
  const envIds = (await EnvironmentModel.find({ projectId }).select("_id").lean()).map((e) => e._id);
  const { purgeResources } = await import("./resource.service.js");
  await Promise.all([
    VariableModel.deleteMany({ environmentId: { $in: envIds } }),
    purgeResources({ environmentId: { $in: envIds } }),
    GrantModel.updateMany({ projectId, revokedAt: null }, { revokedAt: new Date(), revokedBy: actorId }),
    EnvironmentModel.deleteMany({ projectId }),
  ]);
  await ProjectModel.deleteOne({ _id: projectId });
  bus.publish({
    type: "access.revoked",
    scope: "project",
    projectId: projectId.toHexString(),
    reason: "project deleted",
  });
  await recordAudit({ orgId: project.orgId, actorId, action: "project.deleted", target: project.name });
}
