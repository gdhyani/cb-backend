import { startup } from "./lifecycle.js";

startup().catch(() => process.exit(1));
