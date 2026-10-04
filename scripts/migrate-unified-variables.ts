/**
 * PRD v1.26: bring existing services into the Unified Variables format (labels and links only).
 *   npm run migrate:unified-variables            # dry run: prints what would change
 *   npm run migrate:unified-variables -- --apply # writes
 */
import { connectMongo, disconnectMongo } from "../src/clients/mongodb.client.js";
import { loadEnv, setEnv } from "../src/config/env.js";
import { migrateUnifiedVariables } from "../src/migrations/unified-variables.migration.js";

const apply = process.argv.includes("--apply");
const env = loadEnv();
setEnv(env);
await connectMongo(env.MONGODB_URI);
const { changes } = await migrateUnifiedVariables({ apply });
for (const c of changes) console.log(`${apply ? "applied" : "would apply"}: ${c}`);
console.log(`${changes.length} change(s)${apply ? " applied" : " (dry run — add --apply to write)"}`);
await disconnectMongo();
