import { isValidObjectId, Types } from "mongoose";
import { AppError } from "../errors/app-error.js";

/** Parses a route id; malformed ids are reported as not found (no existence leaks). */
export function toObjectId(value: unknown, what: string): Types.ObjectId {
  if (typeof value !== "string" || !isValidObjectId(value)) {
    throw new AppError("NOT_FOUND", { message: `${what} not found.` });
  }
  return new Types.ObjectId(value);
}

export const idOf = (v: { _id: Types.ObjectId } | Types.ObjectId): string =>
  v instanceof Types.ObjectId ? v.toHexString() : v._id.toHexString();
