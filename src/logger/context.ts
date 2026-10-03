import { AsyncLocalStorage } from "node:async_hooks";

export interface LogContext {
  correlationId: string;
  userId?: string;
}

const storage = new AsyncLocalStorage<LogContext>();

export function runWithContext<T>(context: LogContext, fn: () => T): T {
  return storage.run(context, fn);
}

export function getContext(): LogContext | undefined {
  return storage.getStore();
}
