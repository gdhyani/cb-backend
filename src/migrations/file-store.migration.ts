import { getEnv } from "../config/env.js";
import { decryptSecret, type EncryptedSecret } from "../crypto/envelope.js";
import { ResourceModel } from "../models/resource.model.js";
import { saveCaFile, saveSecretFile } from "../services/secret-file.service.js";

/**
 * B10: services saved before the file store keep their service-account JSON / .p8 inline (encrypted) and their CA
 * certificate in config. This moves both into the file store. Idempotent; dry run unless `apply`.
 * Reported changes name the service and what moves — never a value.
 */
export async function migrateFilesToStore({ apply }: { apply: boolean }): Promise<{ changes: string[] }> {
  const changes: string[] = [];
  const key = Buffer.from(getEnv().MASTER_KEY, "base64");
  const rows = await ResourceModel.find({
    $or: [
      {
        kind: { $in: ["google-sa", "apns"] },
        credentials: { $exists: true },
        credentialsFile: { $exists: false },
      },
      { "config.caCert": { $type: "string" } },
    ],
  })
    .select("+credentials +credentialsFile")
    .lean();
  for (const r of rows) {
    const config = (r.config ?? {}) as Record<string, unknown>;
    const moveSecret =
      (r.kind === "google-sa" || r.kind === "apns") && r.credentials && !r.credentialsFile?.path;
    const moveCa = typeof config.caCert === "string" && Boolean(config.caCert);
    const what = [moveSecret && "key file", moveCa && "CA certificate"].filter(Boolean).join(" + ");
    changes.push(`${r.kind} "${r.name}" (${r._id.toHexString()}): ${what} → file store`);
    if (!apply) continue;
    const set: Record<string, unknown> = {};
    const unset: Record<string, 1> = {};
    if (moveSecret) {
      const plaintext = decryptSecret(key, r.credentials as unknown as EncryptedSecret);
      set.credentialsFile = await saveSecretFile(r.orgId, r._id, "credentials", plaintext);
      unset.credentials = 1;
    }
    if (moveCa) {
      set["config.caCertFile"] = await saveCaFile(r.orgId, r._id, String(config.caCert));
      unset["config.caCert"] = 1;
    }
    await ResourceModel.updateOne({ _id: r._id }, { $set: set, $unset: unset });
  }
  return { changes };
}
