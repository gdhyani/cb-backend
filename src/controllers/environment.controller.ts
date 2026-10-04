import type { NextFunction, Request, Response } from "express";
import { toAppError } from "../errors/to-app-error.js";
import { authOf } from "../middlewares/auth.middleware.js";
import * as environmentService from "../services/environment.service.js";
import * as grantService from "../services/grant.service.js";
import * as resourceService from "../services/resource.service.js";
import * as serviceSetup from "../services/service-setup.service.js";
import * as variableService from "../services/variable.service.js";
import { toObjectId } from "../utils/ids.js";
import { sendSuccess } from "../utils/response.js";

const envIdOf = (req: Request) => toObjectId(req.params.envId, "Environment");

export async function getEnvironmentHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    sendSuccess(res, await environmentService.getEnvironment(authOf(res).userId, envIdOf(req)));
  } catch (err) {
    next(toAppError(err, "environment.controller.getEnvironment: failed to load environment"));
  }
}

export async function updateEnvironmentHandler(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  try {
    const input = environmentService.UpdateEnvironmentBody.parse(req.body);
    sendSuccess(res, await environmentService.updateEnvironment(authOf(res).userId, envIdOf(req), input));
  } catch (err) {
    next(toAppError(err, "environment.controller.updateEnvironment: failed to update environment"));
  }
}

export async function deleteEnvironmentHandler(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  try {
    await environmentService.deleteEnvironment(authOf(res).userId, envIdOf(req));
    sendSuccess(res, { deleted: true });
  } catch (err) {
    next(toAppError(err, "environment.controller.deleteEnvironment: failed to delete environment"));
  }
}

export async function listResourcesHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    sendSuccess(res, await resourceService.listResources(authOf(res).userId, envIdOf(req)));
  } catch (err) {
    next(toAppError(err, "environment.controller.listResources: failed to list resources"));
  }
}

export async function createResourceHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const input = resourceService.CreateResourceBody.parse(req.body);
    sendSuccess(res, await resourceService.createResource(authOf(res).userId, envIdOf(req), input), 201);
  } catch (err) {
    next(toAppError(err, "environment.controller.createResource: failed to create resource"));
  }
}

export async function listVariablesHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    sendSuccess(res, await variableService.listVariables(authOf(res).userId, envIdOf(req)));
  } catch (err) {
    next(toAppError(err, "environment.controller.listVariables: failed to list variables"));
  }
}

export async function createVariableHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const input = variableService.CreateVariableBody.parse(req.body);
    sendSuccess(res, await variableService.createVariable(authOf(res).userId, envIdOf(req), input), 201);
  } catch (err) {
    next(toAppError(err, "environment.controller.createVariable: failed to create variable"));
  }
}

export async function previewHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const userId = toObjectId(req.query.userId, "Member").toHexString();
    sendSuccess(res, await variableService.previewEnvironment(authOf(res).userId, envIdOf(req), userId));
  } catch (err) {
    next(toAppError(err, "environment.controller.preview: failed to build developer preview"));
  }
}

export async function createGrantHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const input = grantService.CreateGrantBody.parse(req.body);
    sendSuccess(res, await grantService.createGrant(authOf(res).userId, envIdOf(req), input), 201);
  } catch (err) {
    next(toAppError(err, "environment.controller.createGrant: failed to grant access"));
  }
}

export async function createServiceHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const input = serviceSetup.CreateServiceBody.parse(req.body);
    sendSuccess(res, await serviceSetup.createService(authOf(res).userId, envIdOf(req), input), 201);
  } catch (err) {
    next(toAppError(err, "environment.controller.createService: failed to set up service"));
  }
}
