import { type InferSchemaType, model, Schema } from "mongoose";

/** FR-AUTH-003: one row per issued refresh token; a used token is kept to detect reuse. */
const RefreshTokenSchema = new Schema(
  {
    deviceId: { type: Schema.Types.ObjectId, ref: "Device", required: true, index: true },
    tokenHash: { type: String, required: true, unique: true },
    usedAt: { type: Date, default: null },
    expiresAt: { type: Date, required: true, index: { expires: 0 } },
  },
  { timestamps: true },
);

export type RefreshToken = InferSchemaType<typeof RefreshTokenSchema>;
export const RefreshTokenModel = model("RefreshToken", RefreshTokenSchema);
