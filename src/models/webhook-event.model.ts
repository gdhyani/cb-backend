import { type InferSchemaType, model, Schema } from "mongoose";
import { EncryptedSecretSchema } from "./encrypted-secret.schema.js";

/** FR-WH-001: a verified provider webhook, kept 24 h for delivery and replay (body encrypted, never listed). */
const WebhookEventSchema = new Schema(
  {
    orgId: { type: Schema.Types.ObjectId, ref: "Organization", required: true },
    environmentId: { type: Schema.Types.ObjectId, ref: "Environment", required: true },
    resourceId: { type: Schema.Types.ObjectId, ref: "Resource", required: true },
    provider: { type: String, required: true },
    eventId: { type: String, required: true },
    type: { type: String, default: "" },
    /** Stripe thin payload (v2.core.event): may go to its own path and be signed with its own key's fake. */
    thin: { type: Boolean, default: false },
    /** Provider headers the app may use (event id), never signatures. */
    passHeaders: { type: Schema.Types.Mixed, default: {} },
    body: { type: EncryptedSecretSchema, select: false, default: null },
    /** The object(s) the event describes (routing key) and their direct links (fallback), see routing.ts. */
    primaryIds: { type: [String], default: [] },
    objectIds: { type: [String], default: [] },
    /** sha256 of the exact body: a captured Razorpay request replayed under a new event id is still a duplicate. */
    bodyHash: { type: String, required: true },
    routing: { type: String, enum: ["matched", "unmatched"], required: true },
    routeAttempts: { type: Number, default: 0 },
    nextRouteAt: { type: Date, default: null },
    receivedAt: { type: Date, required: true },
    expiresAt: { type: Date, required: true },
  },
  { timestamps: false },
);
WebhookEventSchema.index({ resourceId: 1, eventId: 1 }, { unique: true });
WebhookEventSchema.index({ resourceId: 1, bodyHash: 1 }, { unique: true });
WebhookEventSchema.index({ environmentId: 1, receivedAt: -1 });
WebhookEventSchema.index({ routing: 1, nextRouteAt: 1 });
WebhookEventSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export type WebhookEvent = InferSchemaType<typeof WebhookEventSchema>;
export const WebhookEventModel = model("WebhookEvent", WebhookEventSchema);
