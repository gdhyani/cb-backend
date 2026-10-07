import { generateKeyPairSync } from "node:crypto";
import mongoose from "mongoose";

/** Every form a stored secret could take if it leaked into a document: raw, base64, base64url. */
function forms(needle: string): string[] {
  const b = Buffer.from(needle);
  return [needle, b.toString("base64"), b.toString("base64url")];
}

/**
 * B2 / S2: dumps every collection of the backend database and returns `<collection>:<first 6 chars>` for each needle
 * found in plaintext. Ciphertext never matches. Needles shorter than 8 chars are refused (they would match noise).
 */
export async function sweep(needles: string[]): Promise<string[]> {
  const short = needles.filter((n) => n.length < 8);
  if (short.length) throw new Error(`sweep needles must be ≥ 8 chars (${short.length} too short)`);
  const db = mongoose.connection.db;
  if (!db) throw new Error("not connected");
  const hits: string[] = [];
  for (const { name } of await db.listCollections().toArray()) {
    const dump = JSON.stringify(await db.collection(name).find().toArray());
    for (const n of needles)
      if (forms(n).some((f) => dump.includes(f))) hits.push(`${name}:${n.slice(0, 6)}`);
  }
  return hits;
}

/** A syntactically real Google service-account key file (fresh RSA key), as an admin would upload it. */
export function serviceAccountJson(
  email = "sa@cb-test.iam.gserviceaccount.com",
  tokenUri = "https://oauth2.googleapis.com/token",
) {
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const private_key = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const json = JSON.stringify({
    type: "service_account",
    project_id: "cb-test",
    private_key_id: "0123456789abcdef",
    private_key,
    client_email: email,
    client_id: "1234567890",
    token_uri: tokenUri,
  });
  return { json, private_key, bodyLines: pemBodyLines(private_key) };
}

/** An APNs-style .p8 (EC P-256, PKCS#8). */
export function p8Key() {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const pem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  return { pem, bodyLines: pemBodyLines(pem) };
}

/** The base64 body lines of a PEM: what a leak of the key would contain even if the armour were stripped. */
export function pemBodyLines(pem: string): string[] {
  return pem.split("\n").filter((l) => l.length >= 40 && !l.startsWith("-----"));
}
