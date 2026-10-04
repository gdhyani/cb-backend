import { EventEmitter } from "node:events";

export type RevocationScope =
  | "grant"
  | "device"
  | "membership"
  | "environment"
  | "project"
  | "org"
  | "resource";

export type BusEvent =
  | { type: "config.changed"; environmentId: string }
  | {
      type: "access.revoked";
      scope: RevocationScope;
      reason: string;
      environmentId?: string;
      projectId?: string;
      orgId?: string;
      userId?: string;
      deviceId?: string;
      resourceId?: string;
    };

/** In-process bus (FR-EVT-001); an interface so Redis or change streams can replace it later. */
export interface EventBus {
  publish(event: BusEvent): void;
  subscribe(listener: (event: BusEvent) => void): () => void;
}

class InProcessBus implements EventBus {
  readonly #emitter = new EventEmitter().setMaxListeners(0);

  publish(event: BusEvent): void {
    this.#emitter.emit("event", event);
  }

  subscribe(listener: (event: BusEvent) => void): () => void {
    this.#emitter.on("event", listener);
    return () => this.#emitter.off("event", listener);
  }
}

export const bus: EventBus = new InProcessBus();
