import { createPrivateKey, createPublicKey, generateKeyPairSync, randomUUID } from "node:crypto";
import { getEnv } from "../config/env.js";
import { decryptSecret, encryptSecret } from "../crypto/envelope.js";
import { signJwt, verifyJwt } from "../crypto/jwt.js";
import { hashToken, newToken } from "../crypto/tokens.js";
import { AppError } from "../errors/app-error.js";
import { bus } from "../events/bus.js";
import { DeviceModel } from "../models/device.model.js";
import { MembershipModel } from "../models/membership.model.js";
import { RefreshTokenModel } from "../models/refresh-token.model.js";
import { SigningKeyModel } from "../models/signing-key.model.js";
import { UserModel } from "../models/user.model.js";
import { recordAudit } from "./audit.service.js";

/** FR-AUTH-004: short-lived access tokens; FR-AUTH-003: rotating refresh tokens (30-day rolling). */
export const ACCESS_TOKEN_TTL_SEC = 15 * 60;
export const REFRESH_TOKEN_TTL_MS = 30 * 86_400_000;
export const REFRESH_TOKEN_PREFIX = "cbr_";
/** Pre-rotation device tokens: accepted as a bearer and exchangeable once for a token pair. */
export const LEGACY_DEVICE_TOKEN_PREFIX = "cbd_";
const ISSUER = "cb";

const masterKey = () => Buffer.from(getEnv().MASTER_KEY, "base64");

interface ActiveKey {
  kid: string;
  privatePem: string;
  publicJwk: Record<string, unknown>;
}
let cached: Promise<ActiveKey> | undefined;

/** The active ES256 key, created on first use and stored encrypted (a lost creation race reads the winner). */
export function signingKey(): Promise<ActiveKey> {
  if (!cached) {
    cached = (async () => {
      const load = async () => {
        const doc = await SigningKeyModel.findOne({ active: true })
          .select("+privateKey")
          .sort({ createdAt: -1 })
          .lean();
        return doc
          ? {
              kid: doc.kid,
              privatePem: decryptSecret(masterKey(), doc.privateKey),
              publicJwk: doc.publicJwk as Record<string, unknown>,
            }
          : undefined;
      };
      const existing = await load();
      if (existing) return existing;
      const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
      const privatePem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
      const publicJwk = publicKey.export({ format: "jwk" }) as Record<string, unknown>;
      const kid = randomUUID();
      await SigningKeyModel.create({
        kid,
        publicJwk,
        privateKey: encryptSecret(masterKey(), privatePem),
      }).catch(() => undefined);
      const created = await load();
      if (!created) throw new Error("token: could not create a signing key");
      return created;
    })();
    cached.catch(() => {
      cached = undefined;
    });
  }
  return cached;
}

/** Tests swap databases between suites. */
export function resetSigningKeyCache(): void {
  cached = undefined;
}

/** `/.well-known/jwks.json` (FR-AUTH-004). */
export async function jwks(): Promise<{ keys: Record<string, unknown>[] }> {
  const active = await signingKey();
  const docs = await SigningKeyModel.find({ active: true }).lean();
  const all = new Map<string, Record<string, unknown>>([[active.kid, active.publicJwk]]);
  for (const d of docs) all.set(d.kid, d.publicJwk as Record<string, unknown>);
  return { keys: [...all].map(([kid, jwk]) => ({ ...jwk, kid, alg: "ES256", use: "sig" })) };
}

/** ES256 JWT with sub (user), did (device) and sid (session = device). */
export async function signAccessToken(
  device: { id: string; userId: string },
  ttlSec = ACCESS_TOKEN_TTL_SEC,
): Promise<{ accessToken: string; accessTokenExpiresAt: string }> {
  const key = await signingKey();
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + ttlSec;
  const accessToken = signJwt(
    "ES256",
    createPrivateKey(key.privatePem),
    { iss: ISSUER, sub: device.userId, did: device.id, sid: device.id, iat, exp, jti: randomUUID() },
    { kid: key.kid },
  );
  return { accessToken, accessTokenExpiresAt: new Date(exp * 1000).toISOString() };
}

/** Verifies signature, issuer and expiry; device/user status is checked by the caller (immediate revocation). */
export async function verifyAccessToken(
  token: string,
): Promise<{ userId: string; deviceId: string } | undefined> {
  const [head] = token.split(".");
  let kid: unknown;
  try {
    kid = (JSON.parse(Buffer.from(head ?? "", "base64url").toString()) as { kid?: unknown }).kid;
  } catch {
    return undefined;
  }
  if (typeof kid !== "string") return undefined;
  const active = cached ? await cached.catch(() => undefined) : undefined;
  const publicJwk =
    active?.kid === kid
      ? active.publicJwk
      : (await SigningKeyModel.findOne({ kid, active: true }).lean())?.publicJwk;
  if (!publicJwk) return undefined;
  const decoded = verifyJwt(token, "ES256", createPublicKey({ key: publicJwk as never, format: "jwk" }));
  const p = decoded?.payload;
  if (!p || p.iss !== ISSUER || typeof p.exp !== "number" || p.exp * 1000 <= Date.now()) return undefined;
  if (typeof p.sub !== "string" || typeof p.did !== "string") return undefined;
  return { userId: p.sub, deviceId: p.did };
}

export interface TokenPair {
  accessToken: string;
  accessTokenExpiresAt: string;
  refreshToken: string;
}

/** A fresh access + refresh pair for a device (login and every refresh). */
export async function issueTokens(device: { id: string; userId: string }): Promise<TokenPair> {
  const refreshToken = newToken(REFRESH_TOKEN_PREFIX);
  await RefreshTokenModel.create({
    deviceId: device.id,
    tokenHash: hashToken(refreshToken),
    expiresAt: new Date(Date.now() + REFRESH_TOKEN_TTL_MS),
  });
  await DeviceModel.updateOne({ _id: device.id }, { expiresAt: new Date(Date.now() + REFRESH_TOKEN_TTL_MS) });
  return { ...(await signAccessToken(device)), refreshToken };
}

/** Theft response: a used refresh token came back, so the whole device session is signed out. */
async function revokeForReuse(deviceId: string, userId: string) {
  await DeviceModel.updateOne({ _id: deviceId }, { revokedAt: new Date() });
  await RefreshTokenModel.deleteMany({ deviceId });
  bus.publish({ type: "access.revoked", scope: "device", deviceId, userId, reason: "refresh token reused" });
  for (const m of await MembershipModel.find({ userId }).lean())
    await recordAudit({
      orgId: m.orgId,
      actorId: userId,
      deviceId,
      action: "device.token_reused",
      outcome: "denied",
    });
}

/** FR-AUTH-003: rotate a refresh token (or exchange a legacy device token once). */
export async function refreshTokens(presented: string): Promise<TokenPair> {
  const now = new Date();
  let device: { _id: { toHexString(): string }; userId: { toHexString(): string } } | null = null;
  if (presented.startsWith(LEGACY_DEVICE_TOKEN_PREFIX)) {
    device = await DeviceModel.findOne({
      tokenHash: hashToken(presented),
      revokedAt: null,
      expiresAt: { $gt: now },
    }).lean();
    if (!device) throw new AppError("INVALID_REFRESH_TOKEN");
    // The legacy token stops working once exchanged.
    await DeviceModel.updateOne({ _id: device._id }, { tokenHash: hashToken(newToken("retired_")) });
  } else {
    const row = await RefreshTokenModel.findOne({ tokenHash: hashToken(presented) });
    if (!row || row.expiresAt <= now) throw new AppError("INVALID_REFRESH_TOKEN");
    device = await DeviceModel.findById(row.deviceId).lean();
    if (!device) throw new AppError("INVALID_REFRESH_TOKEN");
    if (row.usedAt) {
      await revokeForReuse(device._id.toHexString(), device.userId.toHexString());
      throw new AppError("REFRESH_TOKEN_REUSED");
    }
    row.usedAt = now;
    await row.save();
  }
  const full = await DeviceModel.findById(device._id).lean();
  if (!full || full.revokedAt || full.expiresAt <= now) throw new AppError("INVALID_REFRESH_TOKEN");
  if (!(await UserModel.exists({ _id: full.userId, disabledAt: null })))
    throw new AppError("INVALID_REFRESH_TOKEN");
  return issueTokens({ id: full._id.toHexString(), userId: full.userId.toHexString() });
}
