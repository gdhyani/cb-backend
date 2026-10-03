import { type InferSchemaType, model, Schema } from "mongoose";

const EnvironmentSchema = new Schema(
  {
    orgId: { type: Schema.Types.ObjectId, ref: "Organization", required: true, index: true },
    projectId: { type: Schema.Types.ObjectId, ref: "Project", required: true, index: true },
    name: { type: String, required: true, lowercase: true, trim: true },
    killedAt: { type: Date, default: null },
    killedReason: { type: String, default: null },
    version: { type: Number, default: 1 },
  },
  { timestamps: true },
);
EnvironmentSchema.index({ projectId: 1, name: 1 }, { unique: true });

export type Environment = InferSchemaType<typeof EnvironmentSchema>;
export const EnvironmentModel = model("Environment", EnvironmentSchema);
