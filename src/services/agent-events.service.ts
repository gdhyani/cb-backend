import type { Response } from "express";
import { type BusEvent, bus } from "../events/bus.js";
import { logger } from "../logger/logger.js";
import { eventConcerns, type RuntimeSubject, revalidate } from "./runtime-access.service.js";

const HEARTBEAT_MS = 15_000;
const open = new Set<Response>();

function write(res: Response, event: string, data: unknown): void {
  res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
}

/** FR-EVT-002: streams config.changed / access.revoked for one device + environment. */
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
      if (event.environmentId === subject.environmentId)
        write(res, "config.changed", { environmentId: event.environmentId });
      return;
    }
    if (!eventConcerns(event, subject)) return;
    void revalidate(subject).then(
      (reason) => {
        if (reason) write(res, "access.revoked", { scope: event.scope, reason: event.reason });
        else write(res, "config.changed", { environmentId: subject.environmentId });
      },
      (err: unknown) =>
        logger.error(
          `agent-events: revalidation failed — ${err instanceof Error ? err.message : String(err)}`,
        ),
    );
  };
  const unsubscribe = bus.subscribe(onEvent);
  const heartbeat = setInterval(() => write(res, "heartbeat", {}), HEARTBEAT_MS);
  res.on("close", () => {
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
