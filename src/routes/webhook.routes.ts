import { Router } from "express";
import {
  ackHandler,
  ingestHandler,
  listEventsHandler,
  listenHandler,
  redeliverHandler,
  replayHandler,
} from "../controllers/webhook.controller.js";
import { requireAuth } from "../middlewares/auth.middleware.js";

export const webhookRoutes = Router();

// FR-WH-001: providers call this; no session, the signature is the only trust.
webhookRoutes.post("/hooks/:serviceId", ingestHandler);
webhookRoutes.post("/agent/webhooks/listen", requireAuth, listenHandler);
webhookRoutes.post("/agent/webhooks/redeliver", requireAuth, redeliverHandler);
webhookRoutes.post("/agent/webhooks/:deliveryId/ack", requireAuth, ackHandler);
webhookRoutes.get("/environments/:envId/webhook-events", requireAuth, listEventsHandler);
webhookRoutes.post("/webhook-events/:eventId/replay", requireAuth, replayHandler);
