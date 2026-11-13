import express, { type Express } from "express";
import { peekEnv } from "./config/env.js";
import { registerErrorHandlers, registerMiddlewares } from "./middlewares/index.js";
import { registerRoutes } from "./routes/index.js";
import { jwks } from "./services/token.service.js";

export interface AppOptions {
  /** Extra routes mounted before the error handlers (tests). */
  extraRoutes?: (app: Express) => void;
}

export function createApp(opts: AppOptions = {}): Express {
  const app = express();
  // S10: the caller's address (req.ip) comes from X-Forwarded-For only when the proxy is trusted (TRUST_PROXY).
  app.set("trust proxy", peekEnv()?.TRUST_PROXY ?? false);
  registerMiddlewares(app);
  // FR-AUTH-004: public keys for access tokens, standard JWKS shape (not the API envelope).
  app.get("/.well-known/jwks.json", (_req, res, next) => {
    jwks().then((body) => res.json(body), next);
  });
  registerRoutes(app);
  opts.extraRoutes?.(app);
  registerErrorHandlers(app);
  return app;
}
