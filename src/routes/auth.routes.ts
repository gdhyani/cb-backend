import { Router } from "express";
import {
  acceptInviteHandler,
  loginHandler,
  logoutHandler,
  meHandler,
  previewInviteHandler,
  signupHandler,
} from "../controllers/auth.controller.js";
import { csrfIfSession, requireAuth } from "../middlewares/auth.middleware.js";

export const authRoutes = Router();

authRoutes.post("/auth/signup", signupHandler);
authRoutes.post("/auth/login", loginHandler);
authRoutes.post("/auth/logout", requireAuth, logoutHandler);
authRoutes.get("/auth/me", requireAuth, meHandler);
authRoutes.get("/invites/:token", previewInviteHandler);
authRoutes.post("/auth/accept-invite", csrfIfSession, acceptInviteHandler);
