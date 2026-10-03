import { type InferSchemaType, model, Schema } from "mongoose";

const UserSchema = new Schema(
  {
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    name: { type: String, required: true, trim: true },
    passwordHash: { type: String, required: true, select: false },
    disabledAt: { type: Date, default: null },
  },
  { timestamps: true },
);

export type User = InferSchemaType<typeof UserSchema>;
export const UserModel = model("User", UserSchema);
