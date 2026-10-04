import { Router } from "express";
import { agentEventsHandler, bootstrapHandler, heartbeatHandler } from "../controllers/agent.controller.js";
import { requireAuth } from "../middlewares/auth.middleware.js";

export const agentRoutes = Router();

agentRoutes.get("/agent/bootstrap", requireAuth, bootstrapHandler);
agentRoutes.get("/agent/events", requireAuth, agentEventsHandler);
agentRoutes.post("/agent/heartbeat", requireAuth, heartbeatHandler);
