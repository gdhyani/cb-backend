import type { NextFunction, Request, Response } from "express";
import { AppError } from "../errors/app-error.js";
import { toAppError } from "../errors/to-app-error.js";
import { authOf } from "../middlewares/auth.middleware.js";
import * as authService from "../services/auth.service.js";
import * as deviceService from "../services/device.service.js";
import { toObjectId } from "../utils/ids.js";
import { sendSuccess } from "../utils/response.js";

export async function startDeviceHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    sendSuccess(res, await deviceService.startDeviceAuth(deviceService.StartDeviceBody.parse(req.body)), 201);
  } catch (err) {
    next(toAppError(err, "device.controller.start: failed to start device login"));
  }
}

export async function pollDeviceHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    sendSuccess(res, await deviceService.pollDeviceToken(deviceService.PollDeviceBody.parse(req.body)));
  } catch (err) {
    next(toAppError(err, "device.controller.poll: device login not complete"));
  }
}

export async function approveDeviceHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const auth = authOf(res);
    if (auth.kind !== "web")
      throw new AppError("FORBIDDEN", { message: "Approve logins from the dashboard." });
    sendSuccess(
      res,
      await deviceService.approveDeviceAuth(auth.userId, deviceService.ApproveDeviceBody.parse(req.body)),
    );
  } catch (err) {
    next(toAppError(err, "device.controller.approve: failed to approve device login"));
  }
}

export async function listMyDevicesHandler(_req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    sendSuccess(res, await deviceService.listMyDevices(authOf(res).userId));
  } catch (err) {
    next(toAppError(err, "device.controller.listMine: failed to list devices"));
  }
}

export async function revokeDeviceHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    await deviceService.revokeDevice(authOf(res).userId, toObjectId(req.params.deviceId, "Device"));
    sendSuccess(res, { revoked: true });
  } catch (err) {
    next(toAppError(err, "device.controller.revoke: failed to revoke device"));
  }
}

export async function whoamiHandler(_req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const auth = authOf(res);
    sendSuccess(res, { ...(await authService.getMe(auth.userId)), deviceId: auth.deviceId ?? null });
  } catch (err) {
    next(toAppError(err, "device.controller.whoami: failed to load identity"));
  }
}

export async function cliLogoutHandler(_req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const auth = authOf(res);
    if (!auth.deviceId) throw new AppError("FORBIDDEN", { message: "Only CLI devices can log out here." });
    await deviceService.revokeDevice(auth.userId, toObjectId(auth.deviceId, "Device"));
    sendSuccess(res, { loggedOut: true });
  } catch (err) {
    next(toAppError(err, "device.controller.cliLogout: failed to log out device"));
  }
}
