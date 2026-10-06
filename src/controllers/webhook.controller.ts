import type { NextFunction, Request, Response } from "express";
import { toAppError } from "../errors/to-app-error.js";
import { authOf } from "../middlewares/auth.middleware.js";
import { assertRuntimeAccess } from "../services/access.service.js";
import * as bootstrapService from "../services/bootstrap.service.js";
import * as deliveryService from "../services/webhook-delivery.service.js";
import { ingestWebhook } from "../services/webhook-ingress.service.js";
import { connectStripeWebhook } from "../services/webhook-setup.service.js";
import { toObjectId } from "../utils/ids.js";
import { PaginationQuery } from "../utils/pagination.js";
import { sendPaginated, sendSuccess } from "../utils/response.js";
import { deviceAuth } from "./agent.controller.js";

const headerMap = (req: Request) =>
  Object.fromEntries(Object.entries(req.headers).map(([k, v]) => [k, Array.isArray(v) ? v[0] : v]));

/** FR-WH-001: public; the raw body (exact bytes) is what the signature covers. */
export async function ingestHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const body = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
    sendSuccess(res, await ingestWebhook(String(req.params.serviceId), body, headerMap(req), req.ip ?? ""));
  } catch (err) {
    next(toAppError(err, "webhook.controller.ingest: webhook not accepted"));
  }
}

export async function ackHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const auth = deviceAuth(res);
    const body = deliveryService.AckBody.parse(req.body);
    sendSuccess(res, await deliveryService.ackDelivery(auth.deviceId, String(req.params.deliveryId), body));
  } catch (err) {
    next(toAppError(err, "webhook.controller.ack: failed to record the delivery result"));
  }
}

export async function listenHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const auth = deviceAuth(res);
    const body = deliveryService.ListenBody.parse(req.body);
    const { env } = await bootstrapService.resolveEnvironment(auth.userId, body);
    await assertRuntimeAccess(auth.userId, env, { deviceId: auth.deviceId });
    sendSuccess(res, await deliveryService.setListener(auth, env._id, body));
  } catch (err) {
    next(toAppError(err, "webhook.controller.listen: failed to change the listener"));
  }
}

/** `cb run` attached an app: whatever waited for it is pushed now (instead of at the next retry). */
export async function redeliverHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const auth = deviceAuth(res);
    const body = deliveryService.RedeliverBody.parse(req.body);
    const { env } = await bootstrapService.resolveEnvironment(auth.userId, body);
    await assertRuntimeAccess(auth.userId, env, { deviceId: auth.deviceId });
    sendSuccess(res, await deliveryService.redeliverPending(auth.deviceId, env._id));
  } catch (err) {
    next(toAppError(err, "webhook.controller.redeliver: failed to redeliver pending webhooks"));
  }
}

export async function listEventsHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const page = PaginationQuery.parse(req.query);
    const result = await deliveryService.listWebhookEvents(
      authOf(res).userId,
      toObjectId(req.params.envId, "Environment"),
      page,
    );
    sendPaginated(res, result.items, result.pagination);
  } catch (err) {
    next(toAppError(err, "webhook.controller.listEvents: failed to list webhook events"));
  }
}

export async function replayHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    sendSuccess(
      res,
      await deliveryService.replayWebhookEvent(
        authOf(res).userId,
        toObjectId(req.params.eventId, "Webhook event"),
      ),
    );
  } catch (err) {
    next(toAppError(err, "webhook.controller.replay: failed to replay the webhook event"));
  }
}

/** Dashboard "Send to me" for an event nobody owns. */
export async function sendToMeHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    sendSuccess(
      res,
      await deliveryService.sendWebhookToMe(
        authOf(res).userId,
        toObjectId(req.params.eventId, "Webhook event"),
      ),
    );
  } catch (err) {
    next(toAppError(err, "webhook.controller.sendToMe: failed to send the webhook event"));
  }
}

/** Dashboard "Connect Stripe": cb creates the Stripe webhook endpoint with the stored key. */
export async function connectHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    sendSuccess(
      res,
      await connectStripeWebhook(authOf(res).userId, toObjectId(req.params.resourceId, "Webhook")),
    );
  } catch (err) {
    next(toAppError(err, "webhook.controller.connect: failed to connect the Stripe webhook"));
  }
}
