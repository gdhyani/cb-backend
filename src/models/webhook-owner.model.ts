import { type InferSchemaType, model, Schema } from "mongoose";

/**
 * FR-WH-002: which device created a provider object (pi_…, order_…), learned in the HTTP gateway from the device's
 * own fake key. Webhooks about that object go to that device only. First device wins.
 */
const WebhookOwnerSchema = new Schema(
  {
    environmentId: { type: Schema.Types.ObjectId, ref: "Environment", required: true },
    provider: { type: String, required: true },
    objectId: { type: String, required: true },
    deviceId: { type: Schema.Types.ObjectId, ref: "Device", required: true },
    userId: { type: Schema.Types.ObjectId, ref: "User", required: true },
    expiresAt: { type: Date, required: true },
  },
  { timestamps: true },
);
WebhookOwnerSchema.index({ environmentId: 1, provider: 1, objectId: 1 }, { unique: true });
WebhookOwnerSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export type WebhookOwner = InferSchemaType<typeof WebhookOwnerSchema>;
export const WebhookOwnerModel = model("WebhookOwner", WebhookOwnerSchema);
