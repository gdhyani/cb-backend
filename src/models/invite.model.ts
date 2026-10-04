import { type InferSchemaType, model, Schema } from "mongoose";
import { ROLES } from "./membership.model.js";

const InviteSchema = new Schema(
  {
    orgId: { type: Schema.Types.ObjectId, ref: "Organization", required: true, index: true },
    role: { type: String, enum: ROLES, required: true },
    email: { type: String, lowercase: true, trim: true, default: null },
    tokenHash: { type: String, required: true, unique: true },
    createdBy: { type: Schema.Types.ObjectId, ref: "User", required: true },
    expiresAt: { type: Date, required: true },
    usedAt: { type: Date, default: null },
    usedBy: { type: Schema.Types.ObjectId, ref: "User", default: null },
    revokedAt: { type: Date, default: null },
  },
  { timestamps: true },
);

export type Invite = InferSchemaType<typeof InviteSchema>;
export const InviteModel = model("Invite", InviteSchema);
