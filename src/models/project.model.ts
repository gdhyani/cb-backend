import { type InferSchemaType, model, Schema } from "mongoose";

const ProjectSchema = new Schema(
  {
    orgId: { type: Schema.Types.ObjectId, ref: "Organization", required: true, index: true },
    name: { type: String, required: true, trim: true },
    slug: { type: String, required: true, lowercase: true, trim: true },
    description: { type: String, default: "" },
  },
  { timestamps: true },
);
ProjectSchema.index({ orgId: 1, slug: 1 }, { unique: true });

export type Project = InferSchemaType<typeof ProjectSchema>;
export const ProjectModel = model("Project", ProjectSchema);
