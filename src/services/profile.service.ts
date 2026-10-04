import type { Types } from "mongoose";
import { z } from "zod";
import { getEnv } from "../config/env.js";
import { decryptSecret, encryptSecret } from "../crypto/envelope.js";
import { AppError } from "../errors/app-error.js";
import { CredentialProfileModel } from "../models/credential-profile.model.js";
import { EnvironmentModel } from "../models/environment.model.js";
import { GrantModel } from "../models/grant.model.js";
import { type ResourceKind, ResourceModel } from "../models/resource.model.js";
import { activeGrantFilter, coveringGrantFilter, requireMembership } from "./access.service.js";
import { recordAudit } from "./audit.service.js";
import { configAndSecret, UpdateResourceBody } from "./resource.service.js";

export const DEFAULT_PROFILE = "default";
const ProfileName = z
  .string()
  .regex(/^[a-z][a-z0-9-]{0,29}$/, "lowercase letters, digits and dashes, e.g. readonly")
  .refine((n) => n !== DEFAULT_PROFILE, `"${DEFAULT_PROFILE}" is the resource's own credentials`);

/** The same write-only credential fields a resource accepts, one set per profile. */
export const ProfileCredentialsBody = UpdateResourceBody.pick({
  connectionUri: true,
  apiKey: true,
  clientSecret: true,
  accessKeyId: true,
  secretAccessKey: true,
  serviceAccountJson: true,
  privateKey: true,
});
export const CreateProfileBody = ProfileCredentialsBody.extend({ name: ProfileName });

export interface ProfileDto {
  name: string;
  rotatedAt: string | null;
  isDefault: boolean;
}

const masterKey = () => Buffer.from(getEnv().MASTER_KEY, "base64");

async function loadResource(actorId: string, resourceId: Types.ObjectId, minRole: "developer" | "admin") {
  const resource = await ResourceModel.findById(resourceId).lean();
  if (!resource) throw new AppError("NOT_FOUND", { message: "Resource not found." });
  await requireMembership(actorId, resource.orgId, minRole);
  return resource;
}

function secretFor(
  resource: { kind: string; config?: unknown },
  input: z.infer<typeof ProfileCredentialsBody>,
) {
  const { secret } = configAndSecret(
    resource.kind as ResourceKind,
    input,
    (resource.config as Record<string, unknown>) ?? {},
  );
  if (!secret) throw new AppError("VALIDATION_FAILED", { message: "Credentials are required." });
  return secret;
}

export async function listProfiles(actorId: string, resourceId: Types.ObjectId): Promise<ProfileDto[]> {
  const resource = await loadResource(actorId, resourceId, "developer");
  const rows = await CredentialProfileModel.find({ resourceId }).sort({ name: 1 }).lean();
  return [
    { name: DEFAULT_PROFILE, rotatedAt: resource.rotatedAt?.toISOString() ?? null, isDefault: true },
    ...rows.map((p) => ({ name: p.name, rotatedAt: p.rotatedAt.toISOString(), isDefault: false })),
  ];
}

export async function createProfile(
  actorId: string,
  resourceId: Types.ObjectId,
  input: z.infer<typeof CreateProfileBody>,
): Promise<ProfileDto> {
  const resource = await loadResource(actorId, resourceId, "admin");
  if (await CredentialProfileModel.exists({ resourceId, name: input.name }))
    throw new AppError("CONFLICT", {
      message: `A profile named "${input.name}" already exists on this resource.`,
    });
  const { name, ...credentials } = input;
  const profile = await CredentialProfileModel.create({
    orgId: resource.orgId,
    resourceId,
    name,
    credentials: encryptSecret(masterKey(), secretFor(resource, credentials)),
    rotatedAt: new Date(),
  });
  await recordAudit({
    orgId: resource.orgId,
    actorId,
    projectId: resource.projectId,
    environmentId: resource.environmentId,
    resourceId,
    action: "profile.created",
    target: `${resource.name}/${name}`,
  });
  return { name: profile.name, rotatedAt: profile.rotatedAt.toISOString(), isDefault: false };
}

/** Rotation takes effect on the next connection; live tunnels keep their session. */
export async function rotateProfile(
  actorId: string,
  resourceId: Types.ObjectId,
  name: string,
  input: z.infer<typeof ProfileCredentialsBody>,
): Promise<ProfileDto> {
  const resource = await loadResource(actorId, resourceId, "admin");
  const profile = await CredentialProfileModel.findOneAndUpdate(
    { resourceId, name },
    { credentials: encryptSecret(masterKey(), secretFor(resource, input)), rotatedAt: new Date() },
    { returnDocument: "after" },
  ).lean();
  if (!profile) throw new AppError("NOT_FOUND", { message: `Profile "${name}" not found.` });
  await recordAudit({
    orgId: resource.orgId,
    actorId,
    projectId: resource.projectId,
    environmentId: resource.environmentId,
    resourceId,
    action: "profile.rotated",
    target: `${resource.name}/${name}`,
  });
  return { name: profile.name, rotatedAt: profile.rotatedAt.toISOString(), isDefault: false };
}

export async function deleteProfile(
  actorId: string,
  resourceId: Types.ObjectId,
  name: string,
): Promise<void> {
  const resource = await loadResource(actorId, resourceId, "admin");
  const inUse = await GrantModel.countDocuments({
    projectId: resource.projectId,
    resourceProfiles: { $elemMatch: { resourceId, profile: name } },
    ...activeGrantFilter(),
  });
  if (inUse)
    throw new AppError("CONFLICT", {
      message: `Profile "${name}" is assigned in ${inUse} access grant(s). Change those grants first.`,
    });
  const { deletedCount } = await CredentialProfileModel.deleteOne({ resourceId, name });
  if (!deletedCount) throw new AppError("NOT_FOUND", { message: `Profile "${name}" not found.` });
  await recordAudit({
    orgId: resource.orgId,
    actorId,
    projectId: resource.projectId,
    environmentId: resource.environmentId,
    resourceId,
    action: "profile.deleted",
    target: `${resource.name}/${name}`,
  });
}

/** Rejects profile assignments that point at another environment's resource or a missing profile. */
export async function assertProfilesExist(
  /** Environment grants pick from that environment's resources; project grants from any in the project. */
  target: { environmentId?: Types.ObjectId } | { projectId: Types.ObjectId },
  assignments: { resourceId: string; profile: string }[],
): Promise<void> {
  for (const { resourceId, profile } of assignments) {
    const resource = await ResourceModel.exists({ _id: resourceId, ...target });
    if (!resource)
      throw new AppError("VALIDATION_FAILED", {
        details: [
          {
            path: "resourceProfiles",
            message: `Resource ${resourceId} is not in this ${"projectId" in target ? "project" : "environment"}.`,
          },
        ],
      });
    if (profile !== DEFAULT_PROFILE && !(await CredentialProfileModel.exists({ resourceId, name: profile })))
      throw new AppError("VALIDATION_FAILED", {
        details: [
          { path: "resourceProfiles", message: `Profile "${profile}" does not exist on that resource.` },
        ],
      });
  }
}

/** Which credential set a user's tunnels to this resource use (owners/admins without a grant: default). */
export async function resolveProfile(
  userId: string,
  environmentId: string,
  resourceId: string,
): Promise<string> {
  // An environment grant's choice wins over a project-wide grant's.
  const env = await EnvironmentModel.findById(environmentId).select("projectId").lean();
  if (!env) return DEFAULT_PROFILE;
  const grants = await GrantModel.find({ userId, ...coveringGrantFilter(env) }).lean();
  const pick = (scope: "environment" | "project") =>
    grants
      .filter((g) => (g.scope === "project" ? "project" : "environment") === scope)
      .flatMap((g) => g.resourceProfiles ?? [])
      .find((p) => p.resourceId?.toHexString() === resourceId)?.profile;
  return pick("environment") ?? pick("project") ?? DEFAULT_PROFILE;
}

/** Gateway-only (FR-GW-005): the real credential for one profile. Never returned by any API. */
export async function readProfileSecret(
  resourceId: Types.ObjectId,
  name: string,
): Promise<string | undefined> {
  const doc = await CredentialProfileModel.findOne({ resourceId, name }).select("+credentials").lean();
  return doc ? decryptSecret(masterKey(), doc.credentials) : undefined;
}
