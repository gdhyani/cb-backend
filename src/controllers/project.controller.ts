import type { NextFunction, Request, Response } from "express";
import { toAppError } from "../errors/to-app-error.js";
import { authOf } from "../middlewares/auth.middleware.js";
import * as environmentService from "../services/environment.service.js";
import * as grantService from "../services/grant.service.js";
import * as projectService from "../services/project.service.js";
import { toObjectId } from "../utils/ids.js";
import { sendSuccess } from "../utils/response.js";

const projectIdOf = (req: Request) => toObjectId(req.params.projectId, "Project");

export async function listProjectsHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    sendSuccess(
      res,
      await projectService.listProjects(authOf(res).userId, toObjectId(req.params.orgId, "Organization")),
    );
  } catch (err) {
    next(toAppError(err, "project.controller.listProjects: failed to list projects"));
  }
}

export async function createProjectHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const input = projectService.CreateProjectBody.parse(req.body);
    sendSuccess(
      res,
      await projectService.createProject(
        authOf(res).userId,
        toObjectId(req.params.orgId, "Organization"),
        input,
      ),
      201,
    );
  } catch (err) {
    next(toAppError(err, "project.controller.createProject: failed to create project"));
  }
}

export async function findProjectHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const orgId = toObjectId(req.params.orgId, "Organization");
    sendSuccess(
      res,
      await projectService.findProject(authOf(res).userId, orgId, String(req.params.idOrSlug)),
    );
  } catch (err) {
    next(toAppError(err, "project.controller.findProject: failed to find project"));
  }
}

export async function getProjectHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    sendSuccess(res, await projectService.getProject(authOf(res).userId, projectIdOf(req)));
  } catch (err) {
    next(toAppError(err, "project.controller.getProject: failed to load project"));
  }
}

export async function updateProjectHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const input = projectService.UpdateProjectBody.parse(req.body);
    sendSuccess(res, await projectService.updateProject(authOf(res).userId, projectIdOf(req), input));
  } catch (err) {
    next(toAppError(err, "project.controller.updateProject: failed to update project"));
  }
}

export async function deleteProjectHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    await projectService.deleteProject(authOf(res).userId, projectIdOf(req));
    sendSuccess(res, { deleted: true });
  } catch (err) {
    next(toAppError(err, "project.controller.deleteProject: failed to delete project"));
  }
}

export async function listEnvironmentsHandler(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  try {
    sendSuccess(res, await environmentService.listEnvironments(authOf(res).userId, projectIdOf(req)));
  } catch (err) {
    next(toAppError(err, "project.controller.listEnvironments: failed to list environments"));
  }
}

export async function createEnvironmentHandler(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  try {
    const input = environmentService.CreateEnvironmentBody.parse(req.body);
    sendSuccess(
      res,
      await environmentService.createEnvironment(authOf(res).userId, projectIdOf(req), input),
      201,
    );
  } catch (err) {
    next(toAppError(err, "project.controller.createEnvironment: failed to create environment"));
  }
}

export async function getAccessHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    sendSuccess(res, await grantService.getAccessMatrix(authOf(res).userId, projectIdOf(req)));
  } catch (err) {
    next(toAppError(err, "project.controller.getAccess: failed to load access matrix"));
  }
}

export async function setProjectAccessHandler(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  try {
    const input = grantService.SetProjectAccessBody.parse(req.body);
    const userId = toObjectId(req.params.userId, "Member").toHexString();
    sendSuccess(
      res,
      await grantService.setProjectAccess(authOf(res).userId, projectIdOf(req), userId, input),
    );
  } catch (err) {
    next(toAppError(err, "project.controller.setProjectAccess: failed to set project access"));
  }
}

export async function removeProjectAccessHandler(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  try {
    const userId = toObjectId(req.params.userId, "Member").toHexString();
    const revoked = await grantService.removeProjectAccess(authOf(res).userId, projectIdOf(req), userId);
    sendSuccess(res, { revoked });
  } catch (err) {
    next(toAppError(err, "project.controller.removeProjectAccess: failed to remove project access"));
  }
}
