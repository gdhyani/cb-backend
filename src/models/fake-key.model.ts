import { type InferSchemaType, model, Schema } from "mongoose";
import { EncryptedSecretSchema } from "./encrypted-secret.schema.js";

/** FR-CRY-004: fake RSA key material per (device, resource), generated once (deterministic RSA is impractical). */
const FakeKeySchema = new Schema(
  {
    deviceId: { type: Schema.Types.ObjectId, ref: "Device", required: true },
    resourceId: { type: Schema.Types.ObjectId, ref: "Resource", required: true },
    publicPem: { type: String, required: true },
    privateKey: { type: EncryptedSecretSchema, required: true, select: false },
  },
  { timestamps: true },
);
FakeKeySchema.index({ deviceId: 1, resourceId: 1 }, { unique: true });

export type FakeKey = InferSchemaType<typeof FakeKeySchema>;
export const FakeKeyModel = model("FakeKey", FakeKeySchema);
