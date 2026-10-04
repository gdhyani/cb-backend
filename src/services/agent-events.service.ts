import type { Response } from "express";
import { type BusEvent, bus } from "../events/bus.js";
import { logger } from "../logger/logger.js";
import { EnvironmentModel } from "../models/environment.model.js";
import { eventConcerns, type RuntimeSubject, revalidate } from "./runtime-access.service.js";
import { pendingFor, renderPush, streamOpened } from "./webhook-delivery.service.js";

const HEARTBEAT_MS = 15_000;
const open = new Set<Response>();

function write(res: Response, event: string, data: unknown): void {
  res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
}

/** §12.3: config.changed carries the environment's current version so agents can skip stale refreshes. */
async function writeConfigChanged(res: Response, environmentId: string): Promise<void> {
  const env = await EnvironmentModel.findById(environmentId).select("version").lean();
  write(res, "config.changed", { environmentId, version: env?.version ?? 1 });
}

/** FR-WH-003: re-signed for this device right before sending; nothing is written when access is gone. */
async function writeWebhook(res: Response, subject: RuntimeSubject, deliveryId: string): Promise<void> {
  try {
    const push = await renderPush(deliveryId, subject);
    if (push && !res.writableEnded) write(res, "webhook", push);
  } catch (err) {
    logger.error(
      `agent-events: webhook ${deliveryId} not pushed — ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

/** FR-EVT-002: streams config.changed / access.revoked / webhook for one device + environment. */
export function streamAgentEvents(res: Response, subject: RuntimeSubject): void {
  res.writeHead(200, {
    "content-type": "text/event-stream",
    "cache-control": "no-cache, no-transform",
    connection: "keep-alive",
    "x-accel-buffering": "no",
  });
  write(res, "ready", { environmentId: subject.environmentId });
  open.add(res);

  const onEvent = (event: BusEvent) => {
    if (event.type === "config.changed") {
      if (event.environmentId === subject.environmentId) void writeConfigChanged(res, event.environmentId);
      return;
    }
    if (event.type === "webhook.deliver") {
      if (event.deviceId === subject.deviceId && event.environmentId === subject.environmentId)
        void writeWebhook(res, subject, event.deliveryId);
      return;
    }
    if (!eventConcerns(event, subject)) return;
    void revalidate(subject).then(
      (reason) => {
        if (reason) write(res, "access.revoked", { scope: event.scope, reason: event.reason });
        else void writeConfigChanged(res, subject.environmentId);
      },
      (err: unknown) =>
        logger.error(
          `agent-events: revalidation failed — ${err instanceof Error ? err.message : String(err)}`,
        ),
    );
  };
  const unsubscribe = bus.subscribe(onEvent);
  const closeStream = streamOpened(subject.deviceId, subject.environmentId);
  // FR-WH-003: whatever waited while this device was away goes out now, oldest first.
  void pendingFor(subject).then(
    async (ids) => {
      for (const id of ids) await writeWebhook(res, subject, id);
    },
    (err: unknown) =>
      logger.error(`agent-events: pending webhooks — ${err instanceof Error ? err.message : String(err)}`),
  );
  const heartbeat = setInterval(() => write(res, "heartbeat", {}), HEARTBEAT_MS);
  res.on("close", () => {
    closeStream();
    clearInterval(heartbeat);
    unsubscribe();
    open.delete(res);
  });
}

/** Shutdown: end every event stream so the HTTP server can close. */
export function closeAllAgentStreams(): void {
  for (const res of open) res.end();
  open.clear();
}
