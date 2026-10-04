import type { NextFunction, Request, Response } from "express";
import { toAppError } from "../errors/to-app-error.js";
import { authOf } from "../middlewares/auth.middleware.js";
import { requireMembership } from "../services/access.service.js";
import * as auditService from "../services/audit.service.js";
import * as deviceService from "../services/device.service.js";
import * as inviteService from "../services/invite.service.js";
import * as orgService from "../services/org.service.js";
import { toObjectId } from "../utils/ids.js";
import { PaginationQuery } from "../utils/pagination.js";
import { sendPaginated, sendSuccess } from "../utils/response.js";

const orgIdOf = (req: Request) => toObjectId(req.params.orgId, "Organization");

export async function listOrgsHandler(_req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    sendSuccess(res, await orgService.listMyOrgs(authOf(res).userId));
  } catch (err) {
    next(toAppError(err, "org.controller.listOrgs: failed to list organizations"));
  }
}

export async function getOrgHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    sendSuccess(res, await orgService.getOrg(authOf(res).userId, orgIdOf(req)));
  } catch (err) {
    next(toAppError(err, "org.controller.getOrg: failed to load organization"));
  }
}

export async function listMembersHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    sendSuccess(res, await orgService.listMembers(authOf(res).userId, orgIdOf(req)));
  } catch (err) {
    next(toAppError(err, "org.controller.listMembers: failed to list members"));
  }
}

export async function updateMemberHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const { role } = orgService.UpdateRoleBody.parse(req.body);
    sendSuccess(
      res,
      await orgService.updateMemberRole(
        authOf(res).userId,
        orgIdOf(req),
        toObjectId(req.params.userId, "Member"),
        role,
      ),
    );
  } catch (err) {
    next(toAppError(err, "org.controller.updateMember: failed to change member role"));
  }
}

export async function removeMemberHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    await orgService.removeMember(authOf(res).userId, orgIdOf(req), toObjectId(req.params.userId, "Member"));
    sendSuccess(res, { removed: true });
  } catch (err) {
    next(toAppError(err, "org.controller.removeMember: failed to remove member"));
  }
}

export async function createInviteHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const input = inviteService.CreateInviteBody.parse(req.body ?? {});
    sendSuccess(res, await inviteService.createInvite(authOf(res).userId, orgIdOf(req), input), 201);
  } catch (err) {
    next(toAppError(err, "org.controller.createInvite: failed to create invite"));
  }
}

export async function listInvitesHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    sendSuccess(res, await inviteService.listInvites(authOf(res).userId, orgIdOf(req)));
  } catch (err) {
    next(toAppError(err, "org.controller.listInvites: failed to list invites"));
  }
}

export async function revokeInviteHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    await inviteService.revokeInvite(
      authOf(res).userId,
      orgIdOf(req),
      toObjectId(req.params.inviteId, "Invite"),
    );
    sendSuccess(res, { revoked: true });
  } catch (err) {
    next(toAppError(err, "org.controller.revokeInvite: failed to revoke invite"));
  }
}

export async function listOrgDevicesHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    sendSuccess(res, await deviceService.listOrgDevices(authOf(res).userId, orgIdOf(req)));
  } catch (err) {
    next(toAppError(err, "org.controller.listOrgDevices: failed to list devices"));
  }
}

export async function listAuditHandler(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const orgId = orgIdOf(req);
    await requireMembership(authOf(res).userId, orgId, "admin");
    const page = PaginationQuery.parse(req.query);
    const action = typeof req.query.action === "string" ? req.query.action : undefined;
    const category = auditService.AUDIT_CATEGORIES.find((c) => c === req.query.category);
    const result = await auditService.listAudit(orgId, { ...page, action, category });
    sendPaginated(res, result.items, result.pagination);
  } catch (err) {
    next(toAppError(err, "org.controller.listAudit: failed to list audit events"));
  }
}
