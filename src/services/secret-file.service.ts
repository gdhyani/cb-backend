import { createHash, randomBytes, X509Certificate } from "node:crypto";
import type { Types } from "mongoose";
import { getFileStore } from "../clients/file-store.client.js";
import { getEnv } from "../config/env.js";
import { decryptSecret, type EncryptedSecret, encryptSecret } from "../crypto/envelope.js";
import { logger } from "../logger/logger.js";

/** Where an uploaded file lives (B10). Stored on the resource; never sent to a device. */
export interface FileRef {
  store: "mongo" | "supabase";
  path: string;
  /** sha256 of the plaintext: lets an update that re-sends the same file keep the stored object. */
  sha256: string;
  size: number;
}

/** CA certificates also carry what an admin may see: whose CA and until when (public facts, never the PEM). */
export interface CaFileRef extends FileRef {
  subject: string;
  notAfter: string;
}

const masterKey = () => Buffer.from(getEnv().MASTER_KEY, "base64");
const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");

/**
 * Ciphertext cache (never plaintext): avoids a store round trip on every tunnel open. Entries are kept in write order
 * (oldest first), expire after CACHE_MS, and at most SECRET_FILE_CACHE_MAX are held (M4).
 */
const CACHE_MS = 5 * 60_000;
export const SECRET_FILE_CACHE_MAX = 500;
const cache = new Map<string, { at: number; enc: EncryptedSecret }>();

function cachePut(path: string, enc: EncryptedSecret): void {
  const now = Date.now();
  cache.delete(path);
  cache.set(path, { at: now, enc });
  for (const [p, v] of cache) {
    if (cache.size <= SECRET_FILE_CACHE_MAX && now - v.at < CACHE_MS) break;
    cache.delete(p);
  }
}

/** Tests: entries currently cached. */
export const secretFileCacheSize = () => cache.size;

/** Encrypts with the envelope key (FR-CRY-001) and stores only the ciphertext. */
export async function saveSecretFile(
  orgId: Types.ObjectId,
  resourceId: Types.ObjectId,
  field: string,
  plaintext: string,
): Promise<FileRef> {
  const path = `orgs/${orgId.toHexString()}/resources/${resourceId.toHexString()}/${field}-${randomBytes(8).toString("hex")}.enc`;
  const enc = encryptSecret(masterKey(), plaintext);
  // Whatever was cached for this path is stale from the moment a write starts, even if the write fails (M4).
  cache.delete(path);
  await getFileStore().put(path, Buffer.from(JSON.stringify(enc)));
  cachePut(path, enc);
  return { store: getEnv().FILE_STORE, path, sha256: sha256(plaintext), size: Buffer.byteLength(plaintext) };
}

export async function saveCaFile(
  orgId: Types.ObjectId,
  resourceId: Types.ObjectId,
  pem: string,
): Promise<CaFileRef> {
  const ref = await saveSecretFile(orgId, resourceId, "caCert", pem);
  return { ...ref, ...caCertInfo(pem) };
}

/** Whose CA and until when, from the first certificate of a PEM bundle. Throws on an unreadable PEM. */
export function caCertInfo(pem: string): { subject: string; notAfter: string } {
  const first = new X509Certificate(
    pem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/)?.[0] ?? pem,
  );
  return {
    subject: first.subject.replace(/\n/g, ", "),
    notAfter: new Date(first.validTo).toISOString(),
  };
}

/** Decrypts per use (FR-GW-005); the plaintext is never cached. */
export async function readSecretFile(ref: FileRef): Promise<string> {
  const hit = cache.get(ref.path);
  let enc = hit && Date.now() - hit.at < CACHE_MS ? hit.enc : undefined;
  if (!enc) {
    enc = JSON.parse((await getFileStore().get(ref.path)).toString()) as EncryptedSecret;
    cachePut(ref.path, enc);
  }
  return decryptSecret(masterKey(), enc);
}

/** Best effort: a store hiccup never blocks a delete or a rotation; it is logged (path only) for cleanup. */
export async function removeSecretFiles(refs: (FileRef | undefined | null)[]): Promise<void> {
  const paths = refs.filter((r): r is FileRef => Boolean(r?.path)).map((r) => r.path);
  if (!paths.length) return;
  for (const p of paths) cache.delete(p);
  await getFileStore()
    .remove(paths)
    .catch((err: unknown) =>
      logger.warn(
        `file store: could not remove ${paths.join(", ")} — ${err instanceof Error ? err.message : "error"}`,
      ),
    );
}

export const sameFile = (ref: FileRef | undefined, plaintext: string) =>
  Boolean(ref && ref.sha256 === sha256(plaintext));

/** Gateway / connection test: the resource's CA back in `config.caCert`, in memory only. */
export async function withCaCert<T extends { config?: unknown }>(resource: T): Promise<T> {
  const config = (resource.config ?? {}) as Record<string, unknown>;
  const ref = config.caCertFile as CaFileRef | undefined;
  if (!ref || config.caCert) return resource;
  return { ...resource, config: { ...config, caCert: await readSecretFile(ref) } };
}
