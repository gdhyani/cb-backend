import type { AuthContext } from "../middlewares/auth.middleware.js";

declare global {
  namespace Express {
    interface Locals {
      auth?: AuthContext;
      correlationId?: string;
      startedAt?: number;
      errorLogged?: boolean;
    }
  }
}
