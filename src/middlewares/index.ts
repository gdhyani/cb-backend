import express, { type Express } from "express";
import helmet from "helmet";
import { JSON_BODY_LIMIT } from "../constants.js";
import { correlationIdMiddleware } from "./correlation-id.middleware.js";
import { errorHandlerMiddleware } from "./error-handler.middleware.js";
import { notFoundMiddleware } from "./not-found.middleware.js";
import { requestLoggerMiddleware } from "./request-logger.middleware.js";

/** The one place where request middleware and its order are defined. */
export function registerMiddlewares(app: Express): void {
  app.disable("x-powered-by");
  app.use(correlationIdMiddleware);
  app.use(requestLoggerMiddleware);
  app.use(helmet());
  app.use(express.json({ limit: JSON_BODY_LIMIT }));
}

/** Registered after all routes. */
export function registerErrorHandlers(app: Express): void {
  app.use(notFoundMiddleware);
  app.use(errorHandlerMiddleware);
}
