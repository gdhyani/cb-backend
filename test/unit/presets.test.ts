import { describe, expect, it } from "vitest";
import { listPresets } from "../../src/services/preset.service.js";
import { CreateResourceBody } from "../../src/services/resource.service.js";

const PEM = "-----BEGIN PRIVATE KEY-----x";
const SECRET: Record<string, Record<string, string>> = {
  http: { apiKey: "k" },
  oauth: { clientSecret: "s" },
  postgres: { connectionUri: "postgresql://u:p@h:5432/d" },
  mongodb: { connectionUri: "mongodb://u:p@h:27017/d" },
  redis: { connectionUri: "redis://h:6379" },
  smtp: { connectionUri: "smtp://u:p@h:587" },
  aws: { accessKeyId: "AKIA1", secretAccessKey: "12345678" },
  "google-sa": {
    serviceAccountJson: JSON.stringify({ project_id: "p", client_email: "e@p", private_key: PEM }),
  },
  apns: { keyId: "ABC123DEFG", teamId: "DEF123GHIJ", privateKey: PEM },
};

describe("§10.8 presets are valid data (D6)", () => {
  it("every preset's defaults create a valid resource", () => {
    // Presets whose defaults hold an admin-specific placeholder (e.g. R2's <account-id>) are filled in by the admin.
    for (const p of listPresets().filter((x) => !JSON.stringify(x.defaults).includes("<"))) {
      const r = CreateResourceBody.safeParse({ kind: p.kind, name: p.id, ...SECRET[p.kind], ...p.defaults });
      expect(r.success, `${p.id}: ${JSON.stringify(r.error?.issues)}`).toBe(true);
    }
  });

  it("lists the AI providers and sign-in providers by group", () => {
    const ids = (g: string) =>
      listPresets()
        .filter((p) => p.group === g)
        .map((p) => p.id);
    expect(ids("ai")).toEqual(["openai", "anthropic", "gemini", "groq", "mistral", "openrouter"]);
    expect(ids("oauth")).toEqual(["google-oauth", "github-oauth"]);
    const gemini = listPresets().find((p) => p.id === "gemini");
    expect(gemini?.defaults).toMatchObject({ authScheme: "header", authHeader: "x-goog-api-key" });
  });
});
