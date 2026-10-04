import type { NextFunction, Request, Response } from "express";
import { toAppError } from "../errors/to-app-error.js";
import * as presetService from "../services/preset.service.js";
import { sendSuccess } from "../utils/response.js";

export function listPresetsHandler(_req: Request, res: Response, next: NextFunction): void {
  try {
    sendSuccess(res, presetService.listPresets());
  } catch (err) {
    next(toAppError(err, "preset.controller.listPresets: failed to list presets"));
  }
}
