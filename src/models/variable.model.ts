import { type InferSchemaType, model, Schema } from "mongoose";
import { EncryptedSecretSchema } from "./encrypted-secret.schema.js";

export const VARIABLE_TYPES = ["plain", "generated", "visible", "brokered"] as const;
export type VariableType = (typeof VARIABLE_TYPES)[number];

const VariableSchema = new Schema(
  {
    orgId: { type: Schema.Types.ObjectId, ref: "Organization", required: true, index: true },
    environmentId: { type: Schema.Types.ObjectId, ref: "Environment", required: true, index: true },
    key: { type: String, required: true, trim: true },
    type: { type: String, enum: VARIABLE_TYPES, required: true },
    required: { type: Boolean, default: false },
    /** plain */
    value: { type: String, default: null },
    /** generated */
    format: { type: String, default: null },
    /** visible (real value, encrypted at rest) */
    secret: { type: EncryptedSecretSchema, select: false },
    /** brokered */
    resourceId: { type: Schema.Types.ObjectId, ref: "Resource", default: null },
    field: { type: String, default: null },
  },
  { timestamps: true },
);
VariableSchema.index({ environmentId: 1, key: 1 }, { unique: true });

export type Variable = InferSchemaType<typeof VariableSchema>;
export const VariableModel = model("Variable", VariableSchema);
