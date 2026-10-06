import { type InferSchemaType, model, Schema } from "mongoose";

/** FILE_STORE=mongo: uploaded files kept in the backend database. `data` is always cb ciphertext, never plaintext. */
const StoredFileSchema = new Schema(
  {
    path: { type: String, required: true, unique: true },
    data: { type: Buffer, required: true },
  },
  { timestamps: true },
);

export type StoredFile = InferSchemaType<typeof StoredFileSchema>;
export const StoredFileModel = model("StoredFile", StoredFileSchema);
