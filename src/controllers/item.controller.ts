import type { NextFunction, Request, Response } from "express";
import { toAppError } from "../errors/to-app-error.js";
import { authOf } from "../middlewares/auth.middleware.js";
import * as grantService from "../services/grant.service.js";
import * as profileService from "../services/profile.service.js";
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

const resourceIdOf = (req: Request) => toObjectId(req.params.resourceId, "Resource");
const profileNameOf = (req: Request) => String(req.params.name);

export async function listProfilesHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    sendSuccess(res, await profileService.listProfiles(authOf(res).userId, resourceIdOf(req)));
  } catch (err) {
    next(toAppError(err, "item.controller.listProfiles: failed to list credential profiles"));
  }
}

export async function createProfileHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const input = profileService.CreateProfileBody.parse(req.body);
    sendSuccess(res, await profileService.createProfile(authOf(res).userId, resourceIdOf(req), input), 201);
  } catch (err) {
    next(toAppError(err, "item.controller.createProfile: failed to create credential profile"));
  }
}

export async function rotateProfileHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const input = profileService.ProfileCredentialsBody.parse(req.body);
    sendSuccess(
      res,
      await profileService.rotateProfile(authOf(res).userId, resourceIdOf(req), profileNameOf(req), input),
    );
  } catch (err) {
    next(toAppError(err, "item.controller.rotateProfile: failed to rotate credential profile"));
  }
}

export async function deleteProfileHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    await profileService.deleteProfile(authOf(res).userId, resourceIdOf(req), profileNameOf(req));
    sendSuccess(res, { deleted: true });
  } catch (err) {
    next(toAppError(err, "item.controller.deleteProfile: failed to delete credential profile"));
  }
}

export async function updateGrantHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const input = grantService.UpdateGrantBody.parse(req.body);
    sendSuccess(
      res,
      await grantService.updateGrant(authOf(res).userId, toObjectId(req.params.grantId, "Grant"), input),
    );
  } catch (err) {
    next(toAppError(err, "item.controller.updateGrant: failed to update access grant"));
  }
}
