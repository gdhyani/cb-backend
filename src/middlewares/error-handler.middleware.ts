import type { NextFunction, Request, Response } from "express";
import { toAppError } from "../errors/to-app-error.js";
import { logger } from "../logger/logger.js";
import { elapsedMs } from "./request-logger.middleware.js";

function stackOf(value: unknown): string | undefined {
  return value instanceof Error ? value.stack : undefined;
}

/** The one place errors become responses (PRD §12.7). Stacks are logged only for non-operational errors. */
export function errorHandlerMiddleware(err: unknown, req: Request, res: Response, _next: NextFunction): void {
  const appError = toAppError(err, "unhandled: error reached the error handler without controller context");
  const line = `${req.method} ${req.originalUrl} → ${appError.statusCode} ${appError.code} — ${appError.context} (${elapsedMs(res)}ms)`;
  if (appError.isOperational) {
    logger.warn(line);
  } else {
    logger.error(line, { stack: stackOf(appError.cause) ?? appError.stack });
  }
  res.locals.errorLogged = true;
  if (res.headersSent) {
    res.end();
    return;
  }
  res.status(appError.statusCode).json(appError.toBody(String(res.locals.correlationId ?? "")));
}
