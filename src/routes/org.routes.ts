import { Router } from "express";
import {
  activateKillSwitchHandler,
  clearKillSwitchHandler,
  createInviteHandler,
  getMemberAccessHandler,
  getOrgHandler,
  getOrgStatsHandler,
  listAuditHandler,
  listInvitesHandler,
  listKillSwitchesHandler,
  listMembersHandler,
  listOrgDevicesHandler,
  listOrgsHandler,
  listSessionsHandler,
  removeMemberHandler,
  revokeInviteHandler,
  revokeSessionHandler,
  updateMemberHandler,
} from "../controllers/org.controller.js";
import {
  createProjectHandler,
  findProjectHandler,
  listProjectsHandler,
} from "../controllers/project.controller.js";
import { requireAuth } from "../middlewares/auth.middleware.js";

export const orgRoutes = Router();

orgRoutes.use("/orgs", requireAuth);
orgRoutes.get("/orgs", listOrgsHandler);
orgRoutes.get("/orgs/:orgId", getOrgHandler);
orgRoutes.get("/orgs/:orgId/members", listMembersHandler);
orgRoutes.patch("/orgs/:orgId/members/:userId", updateMemberHandler);
orgRoutes.delete("/orgs/:orgId/members/:userId", removeMemberHandler);
orgRoutes.get("/orgs/:orgId/members/:userId/access", getMemberAccessHandler);
orgRoutes.get("/orgs/:orgId/invites", listInvitesHandler);
orgRoutes.post("/orgs/:orgId/invites", createInviteHandler);
orgRoutes.delete("/orgs/:orgId/invites/:inviteId", revokeInviteHandler);
orgRoutes.get("/orgs/:orgId/devices", listOrgDevicesHandler);
orgRoutes.get("/orgs/:orgId/audit", listAuditHandler);
orgRoutes.get("/orgs/:orgId/stats", getOrgStatsHandler);
orgRoutes.get("/orgs/:orgId/sessions", listSessionsHandler);
orgRoutes.get("/orgs/:orgId/killswitches", listKillSwitchesHandler);
orgRoutes.post("/orgs/:orgId/killswitches", activateKillSwitchHandler);
orgRoutes.use("/sessions", requireAuth);
orgRoutes.delete("/sessions/:sessionId", revokeSessionHandler);
orgRoutes.use("/killswitches", requireAuth);
orgRoutes.delete("/killswitches/:killSwitchId", clearKillSwitchHandler);
orgRoutes.get("/orgs/:orgId/projects", listProjectsHandler);
orgRoutes.post("/orgs/:orgId/projects", createProjectHandler);
orgRoutes.get("/orgs/:orgId/projects/:idOrSlug", findProjectHandler);
