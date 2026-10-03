import type { NextFunction, Request, Response } from "express";
import { toAppError } from "../errors/to-app-error.js";
import { authOf } from "../middlewares/auth.middleware.js";
import * as grantService from "../services/grant.service.js";
import * as resourceService from "../services/resource.service.js";
import * as variableService from "../services/variable.service.js";
import { toObjectId } from "../utils/ids.js";
import { sendSuccess } from "../utils/response.js";

export async function updateResourceHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const input = resourceService.UpdateResourceBody.parse(req.body);
    sendSuccess(
      res,
      await resourceService.updateResource(
        authOf(res).userId,
        toObjectId(req.params.resourceId, "Resource"),
        input,
      ),
    );
  } catch (err) {
    next(toAppError(err, "item.controller.updateResource: failed to update resource"));
  }
}

export async function deleteResourceHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    await resourceService.deleteResource(authOf(res).userId, toObjectId(req.params.resourceId, "Resource"));
    sendSuccess(res, { deleted: true });
  } catch (err) {
    next(toAppError(err, "item.controller.deleteResource: failed to delete resource"));
  }
}

export async function updateVariableHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const input = variableService.UpdateVariableBody.parse(req.body);
    sendSuccess(
      res,
      await variableService.updateVariable(
        authOf(res).userId,
        toObjectId(req.params.variableId, "Variable"),
        input,
      ),
    );
  } catch (err) {
    next(toAppError(err, "item.controller.updateVariable: failed to update variable"));
  }
}

export async function deleteVariableHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    await variableService.deleteVariable(authOf(res).userId, toObjectId(req.params.variableId, "Variable"));
    sendSuccess(res, { deleted: true });
  } catch (err) {
    next(toAppError(err, "item.controller.deleteVariable: failed to delete variable"));
  }
}

export async function revokeGrantHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    await grantService.revokeGrant(authOf(res).userId, toObjectId(req.params.grantId, "Grant"));
    sendSuccess(res, { revoked: true });
  } catch (err) {
    next(toAppError(err, "item.controller.revokeGrant: failed to revoke access"));
  }
}
