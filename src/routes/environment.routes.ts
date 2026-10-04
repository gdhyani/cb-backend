import { Router } from "express";
import {
  createGrantHandler,
  createResourceHandler,
  createVariableHandler,
  deleteEnvironmentHandler,
  getEnvironmentHandler,
  listResourcesHandler,
  listVariablesHandler,
  previewHandler,
  updateEnvironmentHandler,
} from "../controllers/environment.controller.js";
import {
  createProfileHandler,
  deleteProfileHandler,
  deleteResourceHandler,
  deleteVariableHandler,
  listProfilesHandler,
  revokeGrantHandler,
  rotateProfileHandler,
  testResourceHandler,
  updateGrantHandler,
  updateResourceHandler,
  updateVariableHandler,
} from "../controllers/item.controller.js";
import { requireAuth } from "../middlewares/auth.middleware.js";

export const environmentRoutes = Router();

for (const prefix of ["/environments", "/resources", "/variables", "/grants"])
  environmentRoutes.use(prefix, requireAuth);
environmentRoutes.get("/environments/:envId", getEnvironmentHandler);
environmentRoutes.patch("/environments/:envId", updateEnvironmentHandler);
environmentRoutes.delete("/environments/:envId", deleteEnvironmentHandler);
environmentRoutes.get("/environments/:envId/resources", listResourcesHandler);
environmentRoutes.post("/environments/:envId/resources", createResourceHandler);
environmentRoutes.get("/environments/:envId/variables", listVariablesHandler);
environmentRoutes.post("/environments/:envId/variables", createVariableHandler);
environmentRoutes.get("/environments/:envId/preview", previewHandler);
environmentRoutes.post("/environments/:envId/grants", createGrantHandler);
environmentRoutes.patch("/resources/:resourceId", updateResourceHandler);
environmentRoutes.delete("/resources/:resourceId", deleteResourceHandler);
environmentRoutes.post("/resources/:resourceId/test", testResourceHandler);
environmentRoutes.get("/resources/:resourceId/profiles", listProfilesHandler);
environmentRoutes.post("/resources/:resourceId/profiles", createProfileHandler);
environmentRoutes.put("/resources/:resourceId/profiles/:name", rotateProfileHandler);
environmentRoutes.delete("/resources/:resourceId/profiles/:name", deleteProfileHandler);
environmentRoutes.patch("/variables/:variableId", updateVariableHandler);
environmentRoutes.delete("/variables/:variableId", deleteVariableHandler);
environmentRoutes.patch("/grants/:grantId", updateGrantHandler);
environmentRoutes.delete("/grants/:grantId", revokeGrantHandler);
