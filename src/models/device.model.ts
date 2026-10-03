import { type InferSchemaType, model, Schema } from "mongoose";

const DeviceSchema = new Schema(
  {
    userId: { type: Schema.Types.ObjectId, ref: "User", required: true, index: true },
    name: { type: String, required: true },
    os: { type: String, default: "unknown" },
    tokenHash: { type: String, required: true, unique: true, select: false },
    expiresAt: { type: Date, required: true },
    lastSeenAt: { type: Date, default: null },
    revokedAt: { type: Date, default: null },
  },
  { timestamps: true },
);

export type Device = InferSchemaType<typeof DeviceSchema>;
export const DeviceModel = model("Device", DeviceSchema);
