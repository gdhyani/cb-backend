import { type InferSchemaType, model, Schema } from "mongoose";

export const KILL_SWITCH_SCOPES = ["org", "environment", "resource", "user", "device"] as const;
export type KillSwitchScope = (typeof KILL_SWITCH_SCOPES)[number];

/** Emergency stop (J7): refuses brokered access at the given scope until cleared. */
const KillSwitchSchema = new Schema(
  {
    orgId: { type: Schema.Types.ObjectId, ref: "Organization", required: true, index: true },
    scope: { type: String, enum: KILL_SWITCH_SCOPES, required: true },
    /** The environment / resource / user / device id; null for the whole organization. */
    targetId: { type: Schema.Types.ObjectId, default: null },
    targetLabel: { type: String, default: "" },
    reason: { type: String, required: true },
    createdBy: { type: Schema.Types.ObjectId, ref: "User", required: true },
    clearedAt: { type: Date, default: null },
    clearedBy: { type: Schema.Types.ObjectId, ref: "User", default: null },
  },
  { timestamps: true },
);
KillSwitchSchema.index({ orgId: 1, clearedAt: 1 });

export type KillSwitch = InferSchemaType<typeof KillSwitchSchema>;
export const KillSwitchModel = model("KillSwitch", KillSwitchSchema);
