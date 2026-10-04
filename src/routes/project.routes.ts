import { Router } from "express";
import {
  createEnvironmentHandler,
  deleteProjectHandler,
  getAccessHandler,
  getProjectHandler,
  listEnvironmentsHandler,
  removeProjectAccessHandler,
  setProjectAccessHandler,
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
projectRoutes.put("/projects/:projectId/access/:userId", setProjectAccessHandler);
projectRoutes.delete("/projects/:projectId/access/:userId", removeProjectAccessHandler);
