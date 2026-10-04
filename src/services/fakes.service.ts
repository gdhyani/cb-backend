import { getEnv } from "../config/env.js";
import { alnum, base32 } from "../crypto/derive.js";

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
