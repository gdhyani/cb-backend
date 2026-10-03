import { Router } from "express";
import { getHealthHandler } from "../controllers/health.controller.js";

export const healthRoutes = Router();

healthRoutes.get("/health", getHealthHandler);
