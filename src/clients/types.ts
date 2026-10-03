import type { Env } from "../config/env.js";

export type ClientHealth = "up" | "down";

/** Every external system lives in its own <name>.client.ts and implements this. */
export interface Client {
  name: string;
  connect(env: Env): Promise<void>;
  disconnect(): Promise<void>;
  health(): ClientHealth;
}
