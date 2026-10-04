import { type InferSchemaType, model, Schema } from "mongoose";

const GrantSchema = new Schema(
  {
    orgId: { type: Schema.Types.ObjectId, ref: "Organization", required: true, index: true },
    projectId: { type: Schema.Types.ObjectId, ref: "Project", required: true, index: true },
    /** "project" grants cover every environment in the project, including ones created later. */
    scope: { type: String, enum: ["environment", "project"], default: "environment" },
    /** Set for environment grants; null for project grants. */
    environmentId: { type: Schema.Types.ObjectId, ref: "Environment", default: null, index: true },
    userId: { type: Schema.Types.ObjectId, ref: "User", required: true, index: true },
    expiresAt: { type: Date, default: null },
    /** Per-resource credential profile; resources not listed use "default". */
    resourceProfiles: {
      type: [{ _id: false, resourceId: { type: Schema.Types.ObjectId, ref: "Resource" }, profile: String }],
      default: [],
    },
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
