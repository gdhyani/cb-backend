import { type InferSchemaType, model, Schema } from "mongoose";

/** FR-WH-002: a device that opted in (`cb webhooks listen`) to events nobody owns, for a limited time. */
const WebhookListenerSchema = new Schema(
  {
    environmentId: { type: Schema.Types.ObjectId, ref: "Environment", required: true },
    deviceId: { type: Schema.Types.ObjectId, ref: "Device", required: true },
    userId: { type: Schema.Types.ObjectId, ref: "User", required: true },
    expiresAt: { type: Date, required: true },
  },
  { timestamps: true },
);
WebhookListenerSchema.index({ environmentId: 1, deviceId: 1 }, { unique: true });
WebhookListenerSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export type WebhookListener = InferSchemaType<typeof WebhookListenerSchema>;
export const WebhookListenerModel = model("WebhookListener", WebhookListenerSchema);
