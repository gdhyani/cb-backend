import type { Express } from "express";
import { API_PREFIX } from "../constants.js";
import { healthRoutes } from "./health.routes.js";

export function registerRoutes(app: Express): void {
  app.use(API_PREFIX, healthRoutes);
}
