import express, { type Express } from "express";
import { registerErrorHandlers, registerMiddlewares } from "./middlewares/index.js";
import { registerRoutes } from "./routes/index.js";

export interface AppOptions {
  /** Extra routes mounted before the error handlers (tests). */
  extraRoutes?: (app: Express) => void;
}

export function createApp(opts: AppOptions = {}): Express {
  const app = express();
  registerMiddlewares(app);
  registerRoutes(app);
  opts.extraRoutes?.(app);
  registerErrorHandlers(app);
  return app;
}
