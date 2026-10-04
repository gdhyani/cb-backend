import type { Types } from "mongoose";
import { getEnv } from "../config/env.js";
import { decryptSecret } from "../crypto/envelope.js";
import { AppError } from "../errors/app-error.js";
import { ResourceModel } from "../models/resource.model.js";

/** Gateway-only: decrypts the real credential for one use (FR-GW-005). Never returned by any API. */
export async function readResourceSecret(resourceId: Types.ObjectId): Promise<string> {
  const doc = await ResourceModel.findById(resourceId).select("+credentials").lean();
  if (!doc?.credentials) throw new AppError("NOT_FOUND", { message: "Resource credentials not found." });
  return decryptSecret(Buffer.from(getEnv().MASTER_KEY, "base64"), doc.credentials);
}
