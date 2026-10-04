import { type InferSchemaType, model, Schema } from "mongoose";
import { EncryptedSecretSchema } from "./encrypted-secret.schema.js";

/** FR-AUTH-004: ES256 key for access tokens; the private half is envelope-encrypted like org CAs. */
const SigningKeySchema = new Schema(
  {
    kid: { type: String, required: true, unique: true },
    publicJwk: { type: Schema.Types.Mixed, required: true },
    privateKey: { type: EncryptedSecretSchema, required: true, select: false },
    active: { type: Boolean, default: true, index: true },
  },
  { timestamps: true },
);

export type SigningKey = InferSchemaType<typeof SigningKeySchema>;
export const SigningKeyModel = model("SigningKey", SigningKeySchema);
