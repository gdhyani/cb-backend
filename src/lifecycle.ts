import type http from "node:http";
import type { AddressInfo } from "node:net";
import { createApp } from "./app.js";
import { clients } from "./clients/index.js";
import type { Client } from "./clients/types.js";
import { type Env, EnvError, loadEnv, setEnv } from "./config/env.js";
import { GRANT_SWEEP_INTERVAL_MS, SHUTDOWN_TIMEOUT_MS } from "./constants.js";
import { logger } from "./logger/logger.js";
import { createServer } from "./server.js";
import { sweepExpiredGrants } from "./services/grant.service.js";

export interface StartupOptions {
  env?: NodeJS.ProcessEnv;
  /** Exit the process when shutdown finishes (false in tests). */
  exitOnShutdown?: boolean;
  installSignalHandlers?: boolean;
}

export interface RunningServer {
  port: number;
  server: http.Server;
  shutdown(reason: string): Promise<void>;
}

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

async function disconnectAll(connected: Client[]): Promise<void> {
  for (const client of [...connected].reverse()) {
    try {
      await client.disconnect();
      logger.info(`${client.name} disconnected`);
    } catch (err) {
      logger.error(`${client.name} disconnect failed — ${message(err)}`);
    }
  }
}

export async function startup(opts: StartupOptions = {}): Promise<RunningServer> {
  const exitOnShutdown = opts.exitOnShutdown ?? true;
  const fail = (err: unknown): never => {
    if (exitOnShutdown) process.exit(1);
    throw err;
  };

  let env: Env;
  try {
    env = loadEnv(opts.env ?? process.env);
  } catch (err) {
    logger.error(err instanceof EnvError ? err.message : `startup: env check failed — ${message(err)}`);
    return fail(err);
  }
  setEnv(env);
  logger.level = env.LOG_LEVEL;

  const connected: Client[] = [];
  for (const client of clients) {
    try {
      await client.connect(env);
      connected.push(client);
      logger.info(`${client.name} connected`);
    } catch (err) {
      logger.error(`startup: ${client.name} connect failed — ${message(err)}`);
      await disconnectAll(connected);
      return fail(err);
    }
  }

  const server = createServer(createApp());
  await new Promise<void>((resolve) => server.listen(env.PORT, resolve));
  const { port } = server.address() as AddressInfo;
  logger.info(`ready on :${port} (env=${env.NODE_ENV})`);

  const sweeper = setInterval(() => {
    sweepExpiredGrants().catch((err: unknown) =>
      logger.error(`grants: expiry sweep failed — ${message(err)}`),
    );
  }, GRANT_SWEEP_INTERVAL_MS);
  sweeper.unref();

  let shuttingDown: Promise<void> | undefined;
  const shutdown = (reason: string, exitCode = 0): Promise<void> => {
    shuttingDown ??= (async () => {
      logger.info(`shutdown started (${reason})`);
      clearInterval(sweeper);
      const force = setTimeout(() => {
        logger.error(`shutdown: connections still open after ${SHUTDOWN_TIMEOUT_MS}ms, forcing close`);
        server.closeAllConnections();
      }, SHUTDOWN_TIMEOUT_MS);
      force.unref();
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
        server.closeIdleConnections();
      });
      clearTimeout(force);
      await disconnectAll(connected);
      logger.info("shutdown complete");
      if (exitOnShutdown) process.exit(exitCode);
    })();
    return shuttingDown;
  };

  if (opts.installSignalHandlers ?? true) {
    process.once("SIGINT", () => void shutdown("SIGINT"));
    process.once("SIGTERM", () => void shutdown("SIGTERM"));
    process.on("uncaughtException", (err) => {
      logger.error(`uncaught exception — ${err.message}`, { stack: err.stack });
      void shutdown("uncaughtException", 1);
    });
    process.on("unhandledRejection", (reason) => {
      logger.error(`unhandled rejection — ${message(reason)}`, {
        stack: reason instanceof Error ? reason.stack : undefined,
      });
      void shutdown("unhandledRejection", 1);
    });
  }

  return { port, server, shutdown: (reason) => shutdown(reason) };
}
