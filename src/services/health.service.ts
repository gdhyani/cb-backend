import { clients } from "../clients/index.js";
import type { ClientHealth } from "../clients/types.js";
import { SERVICE_VERSION } from "../constants.js";

export interface Health {
  status: "ok" | "degraded";
  uptimeSec: number;
  version: string;
  checks: Record<string, ClientHealth>;
}

export async function getHealth(): Promise<Health> {
  const checks = Object.fromEntries(clients.map((c) => [c.name, c.health()]));
  const allUp = Object.values(checks).every((h) => h === "up");
  return {
    status: allUp ? "ok" : "degraded",
    uptimeSec: Math.round(process.uptime()),
    version: SERVICE_VERSION,
    checks,
  };
}
