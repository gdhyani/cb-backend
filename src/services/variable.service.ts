import type { Types } from "mongoose";
import { z } from "zod";
import { getEnv } from "../config/env.js";
import { deriveGenerated, GENERATED_FORMATS, type GeneratedFormat } from "../crypto/derive.js";
import { encryptSecret } from "../crypto/envelope.js";
import { AppError } from "../errors/app-error.js";
import { MembershipModel } from "../models/membership.model.js";
import { type ResourceKind, ResourceModel } from "../models/resource.model.js";
import { UserModel } from "../models/user.model.js";
import { VariableModel, type VariableType } from "../models/variable.model.js";
import { hasEnvironmentAccess, loadEnvironment, requireMembership } from "./access.service.js";
import { recordAudit } from "./audit.service.js";
import { touchEnvironment } from "./environment.service.js";
import { BROKERED_FIELDS } from "./resource.service.js";

const Key = z
  .string()
  .trim()
  .regex(/^[A-Z_][A-Z0-9_]*$/, "use UPPER_SNAKE_CASE");
const Format = z.enum(GENERATED_FORMATS as [GeneratedFormat, ...GeneratedFormat[]]);

export const CreateVariableBody = z.discriminatedUnion("type", [
  z.object({
    type: z.literal("plain"),
    key: Key,
    value: z.string().max(10_000),
    required: z.boolean().default(false),
  }),
  z.object({ type: z.literal("generated"), key: Key, format: Format, required: z.boolean().default(false) }),
  z.object({
    type: z.literal("visible"),
    key: Key,
    value: z.string().min(1).max(10_000),
    required: z.boolean().default(false),
  }),
  z.object({
    type: z.literal("brokered"),
    key: Key,
    resourceId: z.string(),
    field: z.string(),
    required: z.boolean().default(false),
  }),
]);

export const UpdateVariableBody = z.object({
  key: Key.optional(),
  value: z.string().max(10_000).optional(),
  format: Format.optional(),
  resourceId: z.string().optional(),
  field: z.string().optional(),
  required: z.boolean().optional(),
});

export interface VariableDto {
  id: string;
  environmentId: string;
  key: string;
  type: VariableType;
  required: boolean;
  value: string | null;
  format: string | null;
  resourceId: string | null;
  resourceName: string | null;
  field: string | null;
  updatedAt: string;
}

const masterKey = () => Buffer.from(getEnv().MASTER_KEY, "base64");
const serverSecret = () => Buffer.from(getEnv().SERVER_SECRET, "base64");

/** FR-CRY-003: the developer's personal value for a generated variable. */
export function generatedValue(userId: string, envId: string, variableId: string, format: string): string {
  return deriveGenerated(serverSecret(), ["generated", userId, envId, variableId], format as GeneratedFormat);
}

async function assertBrokeredTarget(envId: Types.ObjectId, resourceId: string, field: string) {
  const resource = await ResourceModel.findOne({ _id: resourceId, environmentId: envId }).lean();
  if (!resource)
    throw new AppError("VALIDATION_FAILED", {
      details: [{ path: "resourceId", message: "Pick a resource from this environment." }],
    });
  const allowed = BROKERED_FIELDS[resource.kind as ResourceKind];
  if (!allowed.includes(field)) {
    throw new AppError("VALIDATION_FAILED", {
      details: [{ path: "field", message: `${resource.kind} resources broker: ${allowed.join(", ")}` }],
    });
  }
  return resource;
}

async function toDtos(
  rows: {
    _id: Types.ObjectId;
    environmentId: Types.ObjectId;
    key: string;
    type: string;
    required?: boolean | null;
    value?: string | null;
    format?: string | null;
    resourceId?: Types.ObjectId | null;
    field?: string | null;
    updatedAt?: Date;
  }[],
): Promise<VariableDto[]> {
  const resourceIds = rows.map((r) => r.resourceId).filter((v): v is Types.ObjectId => Boolean(v));
  const names = new Map(
    (await ResourceModel.find({ _id: { $in: resourceIds } }).lean()).map(
      (r) => [r._id.toHexString(), r.name] as const,
    ),
  );
  return rows.map((r) => ({
    id: r._id.toHexString(),
    environmentId: r.environmentId.toHexString(),
    key: r.key,
    type: r.type as VariableType,
    required: Boolean(r.required),
    // Only plain values are readable; visible values are write-only in the dashboard (L15).
    value: r.type === "plain" ? (r.value ?? "") : null,
    format: r.format ?? null,
    resourceId: r.resourceId?.toHexString() ?? null,
    resourceName: r.resourceId ? (names.get(r.resourceId.toHexString()) ?? null) : null,
    field: r.field ?? null,
    updatedAt: (r.updatedAt ?? new Date()).toISOString(),
  }));
}

export async function listVariables(userId: string, envId: Types.ObjectId): Promise<VariableDto[]> {
  await loadEnvironment(userId, envId);
  return toDtos(await VariableModel.find({ environmentId: envId }).sort({ key: 1 }).lean());
}

export async function createVariable(
  actorId: string,
  envId: Types.ObjectId,
  input: z.infer<typeof CreateVariableBody>,
): Promise<VariableDto> {
  const { env } = await loadEnvironment(actorId, envId, "admin");
  if (await VariableModel.exists({ environmentId: envId, key: input.key })) {
    throw new AppError("CONFLICT", { message: `${input.key} already exists in this environment.` });
  }
  const doc: Record<string, unknown> = {
    orgId: env.orgId,
    environmentId: envId,
    key: input.key,
    type: input.type,
    required: input.required,
  };
  if (input.type === "plain") doc.value = input.value;
  if (input.type === "generated") doc.format = input.format;
  if (input.type === "visible") doc.secret = encryptSecret(masterKey(), input.value);
  if (input.type === "brokered") {
    await assertBrokeredTarget(envId, input.resourceId, input.field);
    Object.assign(doc, { resourceId: input.resourceId, field: input.field });
  }
  const created = await VariableModel.create(doc);
  await touchEnvironment(envId);
  await recordAudit({
    orgId: env.orgId,
    actorId,
    projectId: env.projectId,
    environmentId: envId,
    action: "variable.created",
    target: input.key,
    meta: { type: input.type },
  });
  const [dto] = await toDtos([created.toObject()]);
  if (!dto) throw new AppError("INTERNAL_ERROR");
  return dto;
}

export async function updateVariable(
  actorId: string,
  variableId: Types.ObjectId,
  input: z.infer<typeof UpdateVariableBody>,
): Promise<VariableDto> {
  const variable = await VariableModel.findById(variableId);
  if (!variable) throw new AppError("NOT_FOUND", { message: "Variable not found." });
  await requireMembership(actorId, variable.orgId, "admin");
  if (input.key && input.key !== variable.key) {
    if (await VariableModel.exists({ environmentId: variable.environmentId, key: input.key })) {
      throw new AppError("CONFLICT", { message: `${input.key} already exists in this environment.` });
    }
    variable.key = input.key;
  }
  if (input.required !== undefined) variable.required = input.required;
  if (variable.type === "plain" && input.value !== undefined) variable.value = input.value;
  if (variable.type === "generated" && input.format) variable.format = input.format;
  if (variable.type === "visible" && input.value)
    variable.set("secret", encryptSecret(masterKey(), input.value));
  if (variable.type === "brokered" && (input.resourceId || input.field)) {
    const resourceId = input.resourceId ?? variable.resourceId?.toHexString() ?? "";
    const field = input.field ?? variable.field ?? "";
    await assertBrokeredTarget(variable.environmentId, resourceId, field);
    variable.set("resourceId", resourceId);
    variable.field = field;
  }
  await variable.save();
  await touchEnvironment(variable.environmentId);
  await recordAudit({
    orgId: variable.orgId,
    actorId,
    environmentId: variable.environmentId,
    action: "variable.updated",
    target: variable.key,
  });
  const [dto] = await toDtos([variable.toObject()]);
  if (!dto) throw new AppError("INTERNAL_ERROR");
  return dto;
}

export async function deleteVariable(actorId: string, variableId: Types.ObjectId): Promise<void> {
  const variable = await VariableModel.findById(variableId).lean();
  if (!variable) throw new AppError("NOT_FOUND", { message: "Variable not found." });
  await requireMembership(actorId, variable.orgId, "admin");
  await VariableModel.deleteOne({ _id: variableId });
  await touchEnvironment(variable.environmentId);
  await recordAudit({
    orgId: variable.orgId,
    actorId,
    environmentId: variable.environmentId,
    action: "variable.deleted",
    target: variable.key,
  });
}

export interface PreviewEntry {
  key: string;
  type: VariableType;
  display: string;
}

/** J3 "preview as developer": what a given member's app would see (secrets never shown). */
export async function previewEnvironment(actorId: string, envId: Types.ObjectId, userId: string) {
  const { env } = await loadEnvironment(actorId, envId, "admin");
  const member = await MembershipModel.findOne({ orgId: env.orgId, userId }).lean();
  if (!member) throw new AppError("NOT_FOUND", { message: "Member not found." });
  const user = await UserModel.findById(userId).lean();
  const variables = await toDtos(await VariableModel.find({ environmentId: envId }).sort({ key: 1 }).lean());
  const entries: PreviewEntry[] = variables.map((v) => {
    switch (v.type) {
      case "plain":
        return { key: v.key, type: v.type, display: v.value ?? "" };
      case "generated":
        return {
          key: v.key,
          type: v.type,
          display: generatedValue(userId, envId.toHexString(), v.id, v.format ?? "hex:32"),
        };
      case "visible":
        return { key: v.key, type: v.type, display: "•••• real value (visible to the developer)" };
      default:
        return {
          key: v.key,
          type: v.type,
          display: `fake ${v.field} → ${v.resourceName ?? "resource"} via cb (per device)`,
        };
    }
  });
  return {
    user: { id: userId, name: user?.name ?? "", email: user?.email ?? "" },
    hasAccess: await hasEnvironmentAccess(userId, env),
    entries,
  };
}
