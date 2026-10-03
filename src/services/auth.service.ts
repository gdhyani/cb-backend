import { hash, verify } from "@node-rs/argon2";
import { z } from "zod";
import { hashToken, newToken } from "../crypto/tokens.js";
import { AppError } from "../errors/app-error.js";
import { MembershipModel, type Role } from "../models/membership.model.js";
import { OrganizationModel } from "../models/organization.model.js";
import { UserModel } from "../models/user.model.js";
import { WebSessionModel } from "../models/web-session.model.js";
import { recordAudit } from "./audit.service.js";
import { ensureOrgCa } from "./org-ca.service.js";

const SESSION_TTL_MS = 30 * 86_400_000;

export const SignupBody = z.object({
  name: z.string().trim().min(1).max(100),
  email: z.email().max(200),
  password: z.string().min(8, "must be at least 8 characters").max(200),
  orgName: z.string().trim().min(1).max(100),
});
export const LoginBody = z.object({ email: z.email(), password: z.string().min(1) });

export interface UserDto {
  id: string;
  name: string;
  email: string;
}

export interface MeDto {
  user: UserDto;
  memberships: { orgId: string; orgName: string; role: Role }[];
}

export async function hashPassword(password: string): Promise<string> {
  return hash(password);
}

export async function createUser(input: { name: string; email: string; password: string }) {
  const email = input.email.toLowerCase();
  if (await UserModel.exists({ email }))
    throw new AppError("EMAIL_TAKEN", { details: [{ path: "email", message: email }] });
  return UserModel.create({ name: input.name, email, passwordHash: await hashPassword(input.password) });
}

/** J1: account + organization with the user as owner. */
export async function signup(input: z.infer<typeof SignupBody>): Promise<UserDto> {
  const user = await createUser(input);
  const org = await OrganizationModel.create({ name: input.orgName });
  await MembershipModel.create({ orgId: org._id, userId: user._id, role: "owner" });
  await ensureOrgCa(org._id);
  await recordAudit({ orgId: org._id, actorId: user._id, action: "org.created", target: org.name });
  return { id: user._id.toHexString(), name: user.name, email: user.email };
}

export async function login(input: z.infer<typeof LoginBody>): Promise<UserDto> {
  const user = await UserModel.findOne({ email: input.email.toLowerCase(), disabledAt: null }).select(
    "+passwordHash",
  );
  const ok = user ? await verify(user.passwordHash, input.password) : false;
  if (!user || !ok) throw new AppError("INVALID_CREDENTIALS");
  return { id: user._id.toHexString(), name: user.name, email: user.email };
}

export async function createWebSession(
  userId: string,
  userAgent: string,
): Promise<{ token: string; expiresAt: Date }> {
  const token = newToken("cbs_");
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS);
  await WebSessionModel.create({
    userId,
    tokenHash: hashToken(token),
    userAgent: userAgent.slice(0, 300),
    expiresAt,
  });
  return { token, expiresAt };
}

export async function revokeWebSession(sessionId: string): Promise<void> {
  await WebSessionModel.updateOne({ _id: sessionId }, { revokedAt: new Date() });
}

export async function getMe(userId: string): Promise<MeDto> {
  const user = await UserModel.findById(userId).lean();
  if (!user) throw new AppError("UNAUTHORIZED");
  const memberships = await MembershipModel.find({ userId }).lean();
  const orgs = new Map(
    (await OrganizationModel.find({ _id: { $in: memberships.map((m) => m.orgId) } }).lean()).map(
      (o) => [o._id.toHexString(), o.name] as const,
    ),
  );
  return {
    user: { id: user._id.toHexString(), name: user.name, email: user.email },
    memberships: memberships.map((m) => ({
      orgId: m.orgId.toHexString(),
      orgName: orgs.get(m.orgId.toHexString()) ?? "",
      role: m.role as Role,
    })),
  };
}
