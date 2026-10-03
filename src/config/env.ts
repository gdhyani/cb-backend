import { z } from "zod";

const EnvSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().int().min(0).max(65535).default(4200),
  LOG_LEVEL: z.enum(["error", "warn", "info", "http", "debug"]).default("info"),
  MONGODB_URI: z.string().regex(/^mongodb(\+srv)?:\/\//, "must be a mongodb:// or mongodb+srv:// URI"),
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
  if (result.success) return result.data;
  const issues = result.error.issues.map((issue) => {
    const key = String(issue.path[0] ?? "(root)");
    return { key, message: source[key] === undefined ? "is required" : issue.message };
  });
  throw new EnvError(issues);
}
