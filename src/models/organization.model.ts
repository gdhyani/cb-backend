import { type InferSchemaType, model, Schema } from "mongoose";

const OrganizationSchema = new Schema(
  { name: { type: String, required: true, trim: true } },
  { timestamps: true },
);

export type Organization = InferSchemaType<typeof OrganizationSchema>;
export const OrganizationModel = model("Organization", OrganizationSchema);
