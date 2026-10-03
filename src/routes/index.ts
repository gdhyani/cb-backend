import type { Express } from "express";
import { API_PREFIX } from "../constants.js";
import { authRoutes } from "./auth.routes.js";
import { deviceRoutes } from "./device.routes.js";
import { environmentRoutes } from "./environment.routes.js";
import { healthRoutes } from "./health.routes.js";
import { orgRoutes } from "./org.routes.js";
import { projectRoutes } from "./project.routes.js";

export function registerRoutes(app: Express): void {
  app.use(API_PREFIX, healthRoutes, authRoutes, deviceRoutes, orgRoutes, projectRoutes, environmentRoutes);
}
