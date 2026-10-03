import { Router } from "express";
import { agentEventsHandler, bootstrapHandler } from "../controllers/agent.controller.js";
import { requireAuth } from "../middlewares/auth.middleware.js";

export const agentRoutes = Router();

agentRoutes.get("/agent/bootstrap", requireAuth, bootstrapHandler);
agentRoutes.get("/agent/events", requireAuth, agentEventsHandler);
