/**
 * PRD v1.48 (B10): move uploaded files (service-account JSON, .p8, CA certificates) into the file store.
 *   npm run migrate:file-store            # dry run: prints what would move
 *   npm run migrate:file-store -- --apply # writes
 */
import { fileStoreClient } from "../src/clients/file-store.client.js";
import { connectMongo, disconnectMongo } from "../src/clients/mongodb.client.js";
import { loadEnv, setEnv } from "../src/config/env.js";
import { migrateFilesToStore } from "../src/migrations/file-store.migration.js";

const apply = process.argv.includes("--apply");
const env = loadEnv();
setEnv(env);
await connectMongo(env.MONGODB_URI);
await fileStoreClient.connect(env);
const { changes } = await migrateFilesToStore({ apply });
for (const c of changes) console.log(`${apply ? "moved" : "would move"}: ${c}`);
console.log(
  `${changes.length} service(s)${apply ? " moved" : " (dry run — add --apply to write)"} · store: ${env.FILE_STORE}`,
);
await disconnectMongo();
