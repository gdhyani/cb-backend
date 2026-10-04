import { type Env, loadEnv, setEnv } from "../../src/config/env.js";

export const TEST_KEY = Buffer.alloc(32, 3).toString("base64");
export const TEST_SECRET = Buffer.alloc(32, 5).toString("base64");

export function testEnvVars(mongoUri: string): Record<string, string> {
  return {
    NODE_ENV: "test",
    PORT: "0",
    MONGODB_URI: mongoUri,
    MASTER_KEY: TEST_KEY,
    SERVER_SECRET: TEST_SECRET,
  };
}

export function useTestEnv(mongoUri = "mongodb://127.0.0.1:1/unused"): Env {
  const env = loadEnv(testEnvVars(mongoUri));
  setEnv(env);
  return env;
}
