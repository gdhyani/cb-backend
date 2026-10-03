import { z } from "zod";

const base64Key = z
  .string()
  .refine(
    (v) => Buffer.from(v, "base64").length === 32,
    "must be 32 bytes, base64-encoded (openssl rand -base64 32)",
  );

const EnvSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().int().min(0).max(65535).default(4200),
  LOG_LEVEL: z.enum(["error", "warn", "info", "http", "debug"]).default("info"),
  MONGODB_URI: z.string().regex(/^mongodb(\+srv)?:\/\//, "must be a mongodb:// or mongodb+srv:// URI"),
  MASTER_KEY: base64Key,
  SERVER_SECRET: base64Key,
  DASHBOARD_URL: z.url().default("http://localhost:4201"),
  COOKIE_SECURE: z
    .enum(["true", "false"])
    .default("false")
    .transform((v) => v === "true"),
  UPSTREAM_EXTRA_CA_FILE: z.string().optional(),
});

export type Env = z.infer<typeof EnvSchema>;

export interface EnvIssue {
  key: string;
  message: string;
}

export class EnvError extends Error {
  constructor(readonly issues: EnvIssue[]) {
    super(`Invalid environment:\n${issues.map((i) => `  - ${i.key}: ${i.message}`).join("\n")}`);
    this.name = "EnvError";
  }
}

export function loadEnv(source: NodeJS.ProcessEnv = process.env): Env {
  const result = EnvSchema.safeParse(source);
  if (!result.success) {
    const issues = result.error.issues.map((issue) => {
      const key = String(issue.path[0] ?? "(root)");
      return { key, message: source[key] === undefined ? "is required" : issue.message };
    });
    throw new EnvError(issues);
  }
  const env = result.data;
  if (env.NODE_ENV === "production" && env.UPSTREAM_EXTRA_CA_FILE) {
    throw new EnvError([
      { key: "UPSTREAM_EXTRA_CA_FILE", message: "is test-only and refused in production (S11)" },
    ]);
  }
  return env;
}

let current: Env | undefined;

/** Called once by startup (and by tests). */
export function setEnv(env: Env): void {
  current = env;
}

export function getEnv(): Env {
  if (!current) throw new Error("env not initialised: call setEnv() during startup");
  return current;
}
