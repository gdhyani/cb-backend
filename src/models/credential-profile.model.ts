import { type InferSchemaType, model, Schema } from "mongoose";
import { EncryptedSecretSchema } from "./encrypted-secret.schema.js";

/** J2: extra credential sets for one resource (e.g. readonly). The resource's own credentials are "default". */
const CredentialProfileSchema = new Schema(
  {
    orgId: { type: Schema.Types.ObjectId, ref: "Organization", required: true },
    resourceId: { type: Schema.Types.ObjectId, ref: "Resource", required: true },
    name: { type: String, required: true },
    credentials: { type: EncryptedSecretSchema, required: true, select: false },
    rotatedAt: { type: Date, required: true },
  },
  { timestamps: true },
);
CredentialProfileSchema.index({ resourceId: 1, name: 1 }, { unique: true });

export type CredentialProfile = InferSchemaType<typeof CredentialProfileSchema>;
export const CredentialProfileModel = model("CredentialProfile", CredentialProfileSchema);
