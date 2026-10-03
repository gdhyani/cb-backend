import { type InferSchemaType, model, Schema } from "mongoose";

const GrantSchema = new Schema(
  {
    orgId: { type: Schema.Types.ObjectId, ref: "Organization", required: true, index: true },
    projectId: { type: Schema.Types.ObjectId, ref: "Project", required: true, index: true },
    environmentId: { type: Schema.Types.ObjectId, ref: "Environment", required: true, index: true },
    userId: { type: Schema.Types.ObjectId, ref: "User", required: true, index: true },
    expiresAt: { type: Date, default: null },
    createdBy: { type: Schema.Types.ObjectId, ref: "User", required: true },
    revokedAt: { type: Date, default: null },
    revokedBy: { type: Schema.Types.ObjectId, ref: "User", default: null },
    /** Set once the expiry sweeper has announced this temporary grant's end. */
    expiryNotifiedAt: { type: Date, default: null },
  },
  { timestamps: true },
);

export type Grant = InferSchemaType<typeof GrantSchema>;
export const GrantModel = model("Grant", GrantSchema);
