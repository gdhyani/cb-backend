import { Schema } from "mongoose";
import type { EncryptedSecret } from "../crypto/envelope.js";

/** Embedded envelope-encrypted value. Never selected by default. */
export const EncryptedSecretSchema = new Schema<EncryptedSecret>(
  {
    ciphertext: { type: String, required: true },
    iv: { type: String, required: true },
    tag: { type: String, required: true },
    wrappedDek: { type: String, required: true },
    dekIv: { type: String, required: true },
    dekTag: { type: String, required: true },
  },
  { _id: false },
);
