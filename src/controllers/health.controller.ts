import type { NextFunction, Request, Response } from "express";
import { toAppError } from "../errors/to-app-error.js";
import * as healthService from "../services/health.service.js";
import { sendSuccess } from "../utils/response.js";

export async function getHealthHandler(_req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    sendSuccess(res, await healthService.getHealth());
  } catch (err) {
    next(toAppError(err, "health.controller.getHealth: failed to compute health"));
  }
}
