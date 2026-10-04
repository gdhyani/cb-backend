import { type InferSchemaType, model, Schema } from "mongoose";
import { EncryptedSecretSchema } from "./encrypted-secret.schema.js";

/** §10.8 google-sa: fake access token handed to the device → real token used upstream. */
const TokenSwapSchema = new Schema(
  {
    fakeHash: { type: String, required: true, unique: true },
    deviceId: { type: Schema.Types.ObjectId, ref: "Device", required: true },
    resourceId: { type: Schema.Types.ObjectId, ref: "Resource", required: true },
    real: { type: EncryptedSecretSchema, required: true, select: false },
    expiresAt: { type: Date, required: true },
  },
  { timestamps: true },
);
TokenSwapSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export type TokenSwap = InferSchemaType<typeof TokenSwapSchema>;
export const TokenSwapModel = model("TokenSwap", TokenSwapSchema);
