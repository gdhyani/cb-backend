import { type InferSchemaType, model, Schema } from "mongoose";

const DeviceCodeSchema = new Schema(
  {
    userCode: { type: String, required: true, unique: true },
    deviceCodeHash: { type: String, required: true, unique: true },
    deviceName: { type: String, required: true },
    os: { type: String, default: "unknown" },
    approvedBy: { type: Schema.Types.ObjectId, ref: "User", default: null },
    approvedAt: { type: Date, default: null },
    deviceId: { type: Schema.Types.ObjectId, ref: "Device", default: null },
    consumedAt: { type: Date, default: null },
    expiresAt: { type: Date, required: true, index: { expires: 0 } },
  },
  { timestamps: true },
);

export type DeviceCode = InferSchemaType<typeof DeviceCodeSchema>;
export const DeviceCodeModel = model("DeviceCode", DeviceCodeSchema);
