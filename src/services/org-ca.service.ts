import type { Types } from "mongoose";
import { getEnv } from "../config/env.js";
import { type CertKeyPem, createCa } from "../crypto/ca.js";
import { decryptSecret, encryptSecret } from "../crypto/envelope.js";
import { OrgCaModel } from "../models/org-ca.model.js";
import { OrganizationModel } from "../models/organization.model.js";

const masterKey = () => Buffer.from(getEnv().MASTER_KEY, "base64");

/** FR-CRY-005: one CA per organization; the private key is encrypted and never leaves the backend (S5). */
export async function ensureOrgCa(orgId: Types.ObjectId): Promise<string> {
  const existing = await OrgCaModel.findOne({ orgId }).lean();
  if (existing) return existing.certPem;
  const org = await OrganizationModel.findById(orgId).lean();
  const ca = await createCa(`cb org CA (${org?.name ?? orgId.toHexString()})`);
  try {
    await OrgCaModel.create({ orgId, certPem: ca.certPem, key: encryptSecret(masterKey(), ca.keyPem) });
    return ca.certPem;
  } catch {
    // Lost a creation race: use the stored one.
    const stored = await OrgCaModel.findOne({ orgId }).lean();
    if (!stored) throw new Error(`org-ca: could not create CA for ${orgId.toHexString()}`);
    return stored.certPem;
  }
}

export async function loadOrgCa(orgId: Types.ObjectId): Promise<CertKeyPem> {
  await ensureOrgCa(orgId);
  const doc = await OrgCaModel.findOne({ orgId }).select("+key").lean();
  if (!doc?.key) throw new Error(`org-ca: missing CA for ${orgId.toHexString()}`);
  return { certPem: doc.certPem, keyPem: decryptSecret(masterKey(), doc.key) };
}
