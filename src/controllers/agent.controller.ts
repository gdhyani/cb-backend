import type { NextFunction, Request, Response } from "express";
import { AppError } from "../errors/app-error.js";
import { toAppError } from "../errors/to-app-error.js";
import { authOf } from "../middlewares/auth.middleware.js";
import { assertRuntimeAccess } from "../services/access.service.js";
import { streamAgentEvents } from "../services/agent-events.service.js";
import * as bootstrapService from "../services/bootstrap.service.js";
import * as deviceService from "../services/device.service.js";
import { toObjectId } from "../utils/ids.js";
import { sendSuccess } from "../utils/response.js";

export function deviceAuth(res: Response): { userId: string; deviceId: string } {
  const auth = authOf(res);
  if (auth.kind !== "device" || !auth.deviceId) {
    throw new AppError("FORBIDDEN", {
      message: 'This endpoint needs a CLI device token. Run "npx cb login".',
    });
  }
  return { userId: auth.userId, deviceId: auth.deviceId };
}

export async function bootstrapHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const query = bootstrapService.BootstrapQuery.parse(req.query);
    sendSuccess(res, await bootstrapService.buildBootstrap(deviceAuth(res), query));
  } catch (err) {
    next(toAppError(err, "agent.controller.bootstrap: failed to build snapshot"));
  }
}

export async function agentEventsHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const auth = deviceAuth(res);
    const env = await bootstrapService.loadEnvironmentById(toObjectId(req.query.envId, "Environment"));
    if (!env) throw new AppError("NOT_FOUND", { message: "Environment not found." });
    await assertRuntimeAccess(auth.userId, env, { deviceId: auth.deviceId });
    streamAgentEvents(res, {
      ...auth,
      environmentId: env._id.toHexString(),
      projectId: env.projectId.toHexString(),
      orgId: env.orgId.toHexString(),
    });
  } catch (err) {
    next(toAppError(err, "agent.controller.events: failed to open event stream"));
  }
}

export async function heartbeatHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const auth = deviceAuth(res);
    sendSuccess(
      res,
      await deviceService.recordHeartbeat(auth.deviceId, deviceService.HeartbeatBody.parse(req.body)),
    );
  } catch (err) {
    next(toAppError(err, "agent.controller.heartbeat: failed to record heartbeat"));
  }
}
