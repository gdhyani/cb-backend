import { Router } from "express";
import {
  createEnvironmentHandler,
  deleteProjectHandler,
  getAccessHandler,
  getProjectHandler,
  listEnvironmentsHandler,
  updateProjectHandler,
} from "../controllers/project.controller.js";
import { requireAuth } from "../middlewares/auth.middleware.js";

export const projectRoutes = Router();

projectRoutes.use("/projects", requireAuth);
projectRoutes.get("/projects/:projectId", getProjectHandler);
projectRoutes.patch("/projects/:projectId", updateProjectHandler);
projectRoutes.delete("/projects/:projectId", deleteProjectHandler);
projectRoutes.get("/projects/:projectId/environments", listEnvironmentsHandler);
projectRoutes.post("/projects/:projectId/environments", createEnvironmentHandler);
projectRoutes.get("/projects/:projectId/access", getAccessHandler);
