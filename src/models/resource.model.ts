import { type InferSchemaType, model, Schema } from "mongoose";
import { EncryptedSecretSchema } from "./encrypted-secret.schema.js";

export const RESOURCE_KINDS = [
  "mongodb",
  "redis",
  "postgres",
  "mysql",
  "smtp",
  "http",
  "oauth",
  "aws",
  "google-sa",
  "apns",
  /** Webhook signing secret: central ingress verifies with it, devices get per-device fakes (FR-WH-001). */
  "webhook",
] as const;
export type ResourceKind = (typeof RESOURCE_KINDS)[number];

const ResourceSchema = new Schema(
  {
    orgId: { type: Schema.Types.ObjectId, ref: "Organization", required: true, index: true },
    projectId: { type: Schema.Types.ObjectId, ref: "Project", required: true },
    environmentId: { type: Schema.Types.ObjectId, ref: "Environment", required: true, index: true },
    kind: { type: String, enum: RESOURCE_KINDS, required: true },
    name: { type: String, required: true, trim: true },
    /** Non-secret settings (db name, upstream URL, auth scheme, redirect hosts…). */
    config: { type: Schema.Types.Mixed, default: {} },
    /** Write-only real credentials (L15). */
    credentials: { type: EncryptedSecretSchema, select: false },
    rotatedAt: { type: Date, default: null },
    disabledAt: { type: Date, default: null },
  },
  { timestamps: true, minimize: false },
);
ResourceSchema.index({ environmentId: 1, name: 1 }, { unique: true });

export type Resource = InferSchemaType<typeof ResourceSchema>;
export const ResourceModel = model("Resource", ResourceSchema);
