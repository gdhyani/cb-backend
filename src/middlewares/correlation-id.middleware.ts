import { randomUUID } from "node:crypto";
import type { NextFunction, Request, Response } from "express";
import { CORRELATION_HEADER } from "../constants.js";
import { runWithContext } from "../logger/context.js";

const SAFE_ID = /^[A-Za-z0-9._:-]{1,128}$/;

export function correlationIdMiddleware(req: Request, res: Response, next: NextFunction): void {
  const incoming = req.header(CORRELATION_HEADER);
  const correlationId = incoming && SAFE_ID.test(incoming) ? incoming : randomUUID();
  res.locals.correlationId = correlationId;
  res.locals.startedAt = performance.now();
  res.setHeader(CORRELATION_HEADER, correlationId);
  runWithContext({ correlationId }, next);
}
