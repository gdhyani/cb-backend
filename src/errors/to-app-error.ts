import { ZodError } from "zod";
import { AppError } from "./app-error.js";

/** Errors raised by express.json() carry a `type` such as "entity.parse.failed". */
function bodyParserType(err: unknown): string | undefined {
  const type = typeof err === "object" && err !== null ? (err as { type?: unknown }).type : undefined;
  return typeof type === "string" && type.startsWith("entity.") ? type : undefined;
}

function isDuplicateKey(err: unknown): boolean {
  return typeof err === "object" && err !== null && (err as { code?: unknown }).code === 11000;
}

/** Normalizes anything thrown into an AppError and attaches the caller's context string. */
export function toAppError(err: unknown, context: string): AppError {
  if (err instanceof AppError) {
    err.context ??= context;
    return err;
  }
  if (err instanceof ZodError) {
    return new AppError("VALIDATION_FAILED", {
      context,
      cause: err,
      details: err.issues.map((i) => ({ path: i.path.join("."), message: i.message })),
    });
  }
  const parserType = bodyParserType(err);
  if (parserType === "entity.too.large") return new AppError("PAYLOAD_TOO_LARGE", { context, cause: err });
  if (parserType) {
    return new AppError("VALIDATION_FAILED", {
      message: "The request body is not valid JSON.",
      context,
      cause: err,
    });
  }
  if (isDuplicateKey(err)) {
    return new AppError("CONFLICT", { context, cause: err });
  }
  return new AppError("INTERNAL_ERROR", { context, cause: err, isOperational: false });
}
