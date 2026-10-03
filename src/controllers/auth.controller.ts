import type { CookieOptions, NextFunction, Request, Response } from "express";
import { getEnv } from "../config/env.js";
import { toAppError } from "../errors/to-app-error.js";
import { authOf, SESSION_COOKIE } from "../middlewares/auth.middleware.js";
import * as authService from "../services/auth.service.js";
import * as inviteService from "../services/invite.service.js";
import { sendSuccess } from "../utils/response.js";

function cookieOptions(expires: Date): CookieOptions {
  return { httpOnly: true, sameSite: "lax", secure: getEnv().COOKIE_SECURE, expires, path: "/" };
}

async function startSession(req: Request, res: Response, userId: string): Promise<void> {
  const { token, expiresAt } = await authService.createWebSession(userId, req.header("user-agent") ?? "");
  res.cookie(SESSION_COOKIE, token, cookieOptions(expiresAt));
}

export async function signupHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const user = await authService.signup(authService.SignupBody.parse(req.body));
    await startSession(req, res, user.id);
    sendSuccess(res, await authService.getMe(user.id), 201);
  } catch (err) {
    next(toAppError(err, "auth.controller.signup: failed to create account"));
  }
}

export async function loginHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const user = await authService.login(authService.LoginBody.parse(req.body));
    await startSession(req, res, user.id);
    sendSuccess(res, await authService.getMe(user.id));
  } catch (err) {
    next(toAppError(err, "auth.controller.login: failed to log in"));
  }
}

export async function logoutHandler(_req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const auth = authOf(res);
    if (auth.sessionId) await authService.revokeWebSession(auth.sessionId);
    res.clearCookie(SESSION_COOKIE, { path: "/" });
    sendSuccess(res, { loggedOut: true });
  } catch (err) {
    next(toAppError(err, "auth.controller.logout: failed to log out"));
  }
}

export async function meHandler(_req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    sendSuccess(res, await authService.getMe(authOf(res).userId));
  } catch (err) {
    next(toAppError(err, "auth.controller.me: failed to load current user"));
  }
}

export async function previewInviteHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    sendSuccess(res, await inviteService.previewInvite(String(req.params.token)));
  } catch (err) {
    next(toAppError(err, "auth.controller.previewInvite: failed to load invite"));
  }
}

export async function acceptInviteHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const input = inviteService.AcceptInviteBody.parse(req.body);
    const result = await inviteService.acceptInvite(input, res.locals.auth?.userId);
    if (result.created) await startSession(req, res, result.userId);
    sendSuccess(res, { orgId: result.orgId, me: await authService.getMe(result.userId) });
  } catch (err) {
    next(toAppError(err, "auth.controller.acceptInvite: failed to accept invite"));
  }
}
