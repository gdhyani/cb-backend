import { type InferSchemaType, model, Schema } from "mongoose";

export const DELIVERY_STATUSES = ["pending", "delivered", "skipped", "expired"] as const;
export type DeliveryStatus = (typeof DELIVERY_STATUSES)[number];

/** FR-WH-003: one webhook event on its way to one device, until the agent acks it or 24 h pass. */
const WebhookDeliverySchema = new Schema(
  {
    eventRef: { type: Schema.Types.ObjectId, ref: "WebhookEvent", required: true },
    environmentId: { type: Schema.Types.ObjectId, ref: "Environment", required: true },
    resourceId: { type: Schema.Types.ObjectId, ref: "Resource", required: true },
    deviceId: { type: Schema.Types.ObjectId, ref: "Device", required: true },
    userId: { type: Schema.Types.ObjectId, ref: "User", required: true },
    status: { type: String, enum: DELIVERY_STATUSES, default: "pending" },
    attempts: { type: Number, default: 0 },
    /** Incremented by Replay so the agent posts the event again (it dedupes on id + generation). */
    generation: { type: Number, default: 0 },
    nextAttemptAt: { type: Date, required: true },
    lastPushedAt: { type: Date, default: null },
    lastError: { type: String, default: null },
    appStatus: { type: Number, default: null },
    deliveredAt: { type: Date, default: null },
    expiresAt: { type: Date, required: true },
  },
  { timestamps: true },
);
WebhookDeliverySchema.index({ eventRef: 1, deviceId: 1 }, { unique: true });
WebhookDeliverySchema.index({ deviceId: 1, environmentId: 1, status: 1, createdAt: 1 });
WebhookDeliverySchema.index({ status: 1, nextAttemptAt: 1 });
// Rows outlive their event by a day so the dashboard can still say "expired" before they vanish.
WebhookDeliverySchema.index({ expiresAt: 1 }, { expireAfterSeconds: 86_400 });

export type WebhookDelivery = InferSchemaType<typeof WebhookDeliverySchema>;
export const WebhookDeliveryModel = model("WebhookDelivery", WebhookDeliverySchema);
