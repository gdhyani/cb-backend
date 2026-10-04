import {
  createECDH,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  type KeyObject,
} from "node:crypto";
import { getEnv } from "../config/env.js";
import { alnum, base32, deriveBytes } from "../crypto/derive.js";
import { decryptSecret, encryptSecret } from "../crypto/envelope.js";
import { FakeKeyModel } from "../models/fake-key.model.js";

const secret = () => Buffer.from(getEnv().SERVER_SECRET, "base64");

export interface FakeScope {
  deviceId: string;
  environmentId: string;
  resourceId: string;
}

/** FR-CRY-002 / S7: fakes are bound to (device, environment, resource) and worthless anywhere else. */
/** Fake user + password for database-style protocols (redis, postgres, mysql, smtp). */
export function fakeDbCredentials(scope: FakeScope): { username: string; password: string } {
  const parts = ["fake", scope.deviceId, scope.environmentId, scope.resourceId];
  return {
    username: `cbu_${base32(secret(), [...parts, "user"], 8)}`,
    password: alnum(secret(), [...parts, "pass"], 32),
  };
}

export function fakeApiKey(scope: FakeScope, prefix: string): string {
  return `${prefix}${alnum(secret(), ["fake", scope.deviceId, scope.environmentId, scope.resourceId, "key"], 40)}`;
}

/** @deprecated name kept for the redis adapter. */
export const fakeRedisCredentials = fakeDbCredentials;

/** AWS-shaped fakes: access key "AKIACB" + 14 base32 (upper), 40-char secret. */
export function fakeAwsKeys(scope: FakeScope): { accessKeyId: string; secretAccessKey: string } {
  const parts = ["fake", scope.deviceId, scope.environmentId, scope.resourceId];
  return {
    accessKeyId: `AKIACB${base32(secret(), [...parts, "akid"], 14).toUpperCase()}`,
    secretAccessKey: alnum(secret(), [...parts, "aws-secret"], 40),
  };
}

// P-256 group order: a private scalar must be in [1, n).
const P256_N = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");

/** FR-CRY-004: deterministic fake APNs .p8 (EC P-256) per (device, resource); the gateway re-derives it to verify. */
export function fakeApnsKey(scope: Pick<FakeScope, "deviceId" | "resourceId">): {
  privatePem: string;
  publicKey: KeyObject;
} {
  for (let attempt = 0; ; attempt++) {
    const d = deriveBytes(secret(), [scope.deviceId, scope.resourceId, "keymat", String(attempt)], 32);
    const scalar = BigInt(`0x${d.toString("hex")}`);
    if (scalar === 0n || scalar >= P256_N) continue;
    const ecdh = createECDH("prime256v1");
    ecdh.setPrivateKey(d);
    const point = ecdh.getPublicKey();
    const jwk = {
      kty: "EC",
      crv: "P-256",
      d: d.toString("base64url"),
      x: point.subarray(1, 33).toString("base64url"),
      y: point.subarray(33, 65).toString("base64url"),
    };
    const key = createPrivateKey({ key: jwk, format: "jwk" });
    return {
      privatePem: key.export({ type: "pkcs8", format: "pem" }).toString(),
      publicKey: createPublicKey(key),
    };
  }
}

/** FR-CRY-004: fake Google service-account RSA key per (device, resource), created once and stored encrypted. */
export async function fakeGoogleKey(
  scope: Pick<FakeScope, "deviceId" | "resourceId">,
): Promise<{ privatePem: string; publicPem: string }> {
  const masterKey = Buffer.from(getEnv().MASTER_KEY, "base64");
  const filter = { deviceId: scope.deviceId, resourceId: scope.resourceId };
  const existing = await FakeKeyModel.findOne(filter).select("+privateKey").lean();
  if (existing)
    return { privatePem: decryptSecret(masterKey, existing.privateKey), publicPem: existing.publicPem };
  const pair = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  // Concurrent first bootstraps: the unique index keeps one; whoever loses reads the winner's key.
  await FakeKeyModel.updateOne(
    filter,
    {
      $setOnInsert: {
        ...filter,
        publicPem: pair.publicKey,
        privateKey: encryptSecret(masterKey, pair.privateKey),
      },
    },
    { upsert: true },
  ).catch((err: { code?: number }) => {
    if (err.code !== 11000) throw err;
  });
  const stored = await FakeKeyModel.findOne(filter).select("+privateKey").lean();
  if (!stored) throw new Error("fake key not stored");
  return { privatePem: decryptSecret(masterKey, stored.privateKey), publicPem: stored.publicPem };
}

/** Public half only (gateway verification); never decrypts the private key. */
export async function fakeGooglePublicKey(
  scope: Pick<FakeScope, "deviceId" | "resourceId">,
): Promise<string | undefined> {
  return (await FakeKeyModel.findOne({ deviceId: scope.deviceId, resourceId: scope.resourceId }).lean())
    ?.publicPem;
}

/** MongoDB SCRAM-SHA-256 fake: the db-style user/password plus a derived salt (the gateway is the SCRAM server). */
export function fakeScramMaterial(scope: FakeScope) {
  const { username, password } = fakeDbCredentials(scope);
  const parts = ["fake", scope.deviceId, scope.environmentId, scope.resourceId, "scram-salt"];
  return { username, password, salt: deriveBytes(secret(), parts, 16), iterations: 15000 };
}
