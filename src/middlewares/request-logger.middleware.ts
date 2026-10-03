import { STATUS_CODES } from "node:http";
import type { NextFunction, Request, Response } from "express";
import { logger } from "../logger/logger.js";

export function elapsedMs(res: Response): number {
  return Math.round(performance.now() - Number(res.locals.startedAt ?? performance.now()));
}

/** One line per request: "GET /api/health → 200 OK 3ms". Errored requests are logged by the error handler. */
export function requestLoggerMiddleware(req: Request, res: Response, next: NextFunction): void {
  res.on("finish", () => {
    if (res.locals.errorLogged) return;
    const line = `${req.method} ${req.originalUrl} → ${res.statusCode} ${STATUS_CODES[res.statusCode] ?? ""} ${elapsedMs(res)}ms`;
    if (res.statusCode >= 500) logger.error(line);
    else if (res.statusCode >= 400) logger.warn(line);
    else logger.info(line);
  });
  next();
}
