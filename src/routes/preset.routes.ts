import { Router } from "express";
import { listPresetsHandler } from "../controllers/preset.controller.js";
import { requireAuth } from "../middlewares/auth.middleware.js";

export const presetRoutes = Router();

presetRoutes.get("/presets", requireAuth, listPresetsHandler);
