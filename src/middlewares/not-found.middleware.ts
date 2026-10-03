import type { NextFunction, Request, Response } from "express";
import { AppError } from "../errors/app-error.js";

export function notFoundMiddleware(req: Request, _res: Response, next: NextFunction): void {
  next(new AppError("ROUTE_NOT_FOUND", { context: `router: no route for ${req.method} ${req.originalUrl}` }));
}
