import type { Types } from "mongoose";
import { type ResourceKind, ResourceModel } from "../models/resource.model.js";
import { VariableModel } from "../models/variable.model.js";
import { listPresets } from "../services/preset.service.js";
import { MAIN_FIELD } from "../services/resource.service.js";

/**
 * PRD v1.26 data migration: brings services created with the old two-page flow into the Unified Variables format.
 * Labels and links only — credentials and what apps receive are never changed. Idempotent; dry run by default.
 *  1. http services remember the preset that matches their upstream host (`config.provider`) and its `testPath`.
 *  2. A service is named after its main key (the variable on its main field) when that name is free.
 *  3. A plain "…_ID" partner of a "…_SECRET" main key (OAUTH_CLIENT_ID ↔ OAUTH_CLIENT_SECRET) links to the service.
 */
export async function migrateUnifiedVariables({ apply }: { apply: boolean }): Promise<{ changes: string[] }> {
  const changes: string[] = [];
  const presets = listPresets();
  const hostOf = (url: unknown) => {
    try {
      return new URL(String(url)).hostname;
    } catch {
      return "";
    }
  };

  const resources = await ResourceModel.find({}).sort({ createdAt: 1 }).lean();
  for (const r of resources) {
    const kind = r.kind as ResourceKind;
    const config = (r.config ?? {}) as Record<string, unknown>;
    const label = `${String(r.environmentId)}/${r.name}`;
    const update: Record<string, unknown> = {};

    // 1. Preset hint + authenticated test path for API services.
    if (kind === "http") {
      const preset =
        presets.find((p) => p.id === config.provider) ??
        presets.find(
          (p) => p.kind === "http" && hostOf(p.defaults.upstreamUrl) === hostOf(config.upstreamUrl),
        );
      if (preset && !config.provider) {
        update["config.provider"] = preset.id;
        changes.push(`${label}: provider = ${preset.id}`);
      }
      if (preset?.defaults.testPath && !config.testPath) {
        update["config.testPath"] = preset.defaults.testPath;
        changes.push(`${label}: testPath = ${String(preset.defaults.testPath)}`);
      }
    }

    // 2. Name after the main key, when that name is free in the environment.
    const main = await VariableModel.findOne({
      resourceId: r._id,
      type: "brokered",
      field: MAIN_FIELD[kind],
    }).lean();
    if (main && main.key !== r.name) {
      const taken = await ResourceModel.exists({
        environmentId: r.environmentId,
        name: main.key,
        _id: { $ne: r._id },
      });
      if (!taken) {
        update.name = main.key;
        changes.push(`${label}: name → ${main.key}`);
      }
    }

    // 3. Link the plain "_ID" partner of a "_SECRET" main key.
    if (main?.key.endsWith("_SECRET")) {
      const partnerKey = `${main.key.slice(0, -"_SECRET".length)}_ID`;
      const partner = await VariableModel.findOne({
        environmentId: r.environmentId,
        key: partnerKey,
        type: "plain",
        resourceId: null,
      }).lean();
      if (partner) {
        changes.push(`${label}: link ${partnerKey}`);
        if (apply)
          await VariableModel.updateOne({ _id: partner._id }, { resourceId: r._id as Types.ObjectId });
      }
    }

    if (apply && Object.keys(update).length > 0)
      await ResourceModel.updateOne({ _id: r._id }, { $set: update });
  }
  return { changes };
}
