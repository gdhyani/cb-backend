import { type InferSchemaType, model, Schema } from "mongoose";

const AuditEventSchema = new Schema(
  {
    orgId: { type: Schema.Types.ObjectId, ref: "Organization", required: true },
    actorId: { type: Schema.Types.ObjectId, ref: "User", default: null },
    deviceId: { type: Schema.Types.ObjectId, ref: "Device", default: null },
    projectId: { type: Schema.Types.ObjectId, ref: "Project", default: null },
    environmentId: { type: Schema.Types.ObjectId, ref: "Environment", default: null },
    resourceId: { type: Schema.Types.ObjectId, ref: "Resource", default: null },
    action: { type: String, required: true },
    outcome: { type: String, enum: ["success", "denied", "error"], default: "success" },
    target: { type: String, default: null },
    meta: { type: Schema.Types.Mixed, default: {} },
  },
  { timestamps: { createdAt: true, updatedAt: false } },
);
AuditEventSchema.index({ orgId: 1, createdAt: -1 });

export type AuditEvent = InferSchemaType<typeof AuditEventSchema>;
export const AuditEventModel = model("AuditEvent", AuditEventSchema);
