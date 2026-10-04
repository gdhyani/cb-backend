import { type InferSchemaType, model, Schema } from "mongoose";
import { EncryptedSecretSchema } from "./encrypted-secret.schema.js";

const OrgCaSchema = new Schema(
  {
    orgId: { type: Schema.Types.ObjectId, ref: "Organization", required: true, unique: true },
    certPem: { type: String, required: true },
    key: { type: EncryptedSecretSchema, required: true, select: false },
  },
  { timestamps: true },
);

export type OrgCa = InferSchemaType<typeof OrgCaSchema>;
export const OrgCaModel = model("OrgCa", OrgCaSchema);
