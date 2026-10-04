import { z } from "zod";
import { RESOURCE_KINDS } from "../models/resource.model.js";
import raw from "../presets/presets.json" with { type: "json" };

/** §10.8: presets are data, validated once at startup — adding a provider never adds a code path. */
const PresetSchema = z.object({
  id: z.string().regex(/^[a-z0-9-]+$/),
  name: z.string(),
  category: z.enum(["AI", "Payments", "Auth", "Push", "Storage", "Email", "Database"]),
  /** D6: providers listed inside one dashboard type (AI API key, sign-in). */
  group: z.enum(["ai", "oauth"]).optional(),
  kind: z.enum(RESOURCE_KINDS),
  description: z.string(),
  /** Non-secret create fields (upstream URL, auth scheme, redirect hosts, region…). */
  defaults: z.record(z.string(), z.unknown()),
  secretPlaceholder: z.string(),
  /** Brokered variables the preset suggests (key → resource field). */
  variables: z.array(z.object({ key: z.string(), field: z.string() })),
  /** Non-secret values the admin types in (client ids, key ids). */
  plainVariables: z.array(z.object({ key: z.string(), hint: z.string() })).optional(),
});
export type Preset = z.infer<typeof PresetSchema>;

const PRESETS: Preset[] = z.array(PresetSchema).parse(raw);

export function listPresets(): Preset[] {
  return PRESETS;
}

export function getPreset(id: string): Preset | undefined {
  return PRESETS.find((p) => p.id === id);
}
