import { type InferSchemaType, model, Schema } from "mongoose";

export const ROLES = ["owner", "admin", "developer"] as const;
export type Role = (typeof ROLES)[number];

const MembershipSchema = new Schema(
  {
    orgId: { type: Schema.Types.ObjectId, ref: "Organization", required: true, index: true },
    userId: { type: Schema.Types.ObjectId, ref: "User", required: true, index: true },
    role: { type: String, enum: ROLES, required: true },
  },
  { timestamps: true },
);
MembershipSchema.index({ orgId: 1, userId: 1 }, { unique: true });

export type Membership = InferSchemaType<typeof MembershipSchema>;
export const MembershipModel = model("Membership", MembershipSchema);
