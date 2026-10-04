import { type InferSchemaType, model, Schema } from "mongoose";

const WebSessionSchema = new Schema(
  {
    userId: { type: Schema.Types.ObjectId, ref: "User", required: true, index: true },
    tokenHash: { type: String, required: true, unique: true },
    userAgent: { type: String, default: "" },
    expiresAt: { type: Date, required: true, index: { expires: 0 } },
    revokedAt: { type: Date, default: null },
    lastSeenAt: { type: Date, default: null },
  },
  { timestamps: true },
);

export type WebSession = InferSchemaType<typeof WebSessionSchema>;
export const WebSessionModel = model("WebSession", WebSessionSchema);
