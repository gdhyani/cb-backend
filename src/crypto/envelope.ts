import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

/** Stored form of an encrypted secret (FR-CRY-001). Kept behind this module so KMS can replace MASTER_KEY later. */
export interface EncryptedSecret {
  ciphertext: string;
  iv: string;
  tag: string;
  wrappedDek: string;
  dekIv: string;
  dekTag: string;
}

function seal(key: Buffer, plaintext: Buffer): { ciphertext: Buffer; iv: Buffer; tag: Buffer } {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { ciphertext, iv, tag: cipher.getAuthTag() };
}

function open(key: Buffer, ciphertext: Buffer, iv: Buffer, tag: Buffer): Buffer {
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

export function encryptSecret(masterKey: Buffer, plaintext: string): EncryptedSecret {
  const dek = randomBytes(32);
  const data = seal(dek, Buffer.from(plaintext, "utf8"));
  const wrapped = seal(masterKey, dek);
  dek.fill(0);
  return {
    ciphertext: data.ciphertext.toString("base64"),
    iv: data.iv.toString("base64"),
    tag: data.tag.toString("base64"),
    wrappedDek: wrapped.ciphertext.toString("base64"),
    dekIv: wrapped.iv.toString("base64"),
    dekTag: wrapped.tag.toString("base64"),
  };
}

export function decryptSecret(masterKey: Buffer, secret: EncryptedSecret): string {
  const b = (v: string) => Buffer.from(v, "base64");
  const dek = open(masterKey, b(secret.wrappedDek), b(secret.dekIv), b(secret.dekTag));
  try {
    return open(dek, b(secret.ciphertext), b(secret.iv), b(secret.tag)).toString("utf8");
  } finally {
    dek.fill(0);
  }
}
