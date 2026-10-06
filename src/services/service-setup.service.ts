import type { Types } from "mongoose";
import { z } from "zod";
import { AppError } from "../errors/app-error.js";
import { type ResourceKind, ResourceModel } from "../models/resource.model.js";
import { VariableModel } from "../models/variable.model.js";
import { loadEnvironment } from "./access.service.js";
import { touchEnvironment } from "./environment.service.js";
import { getPreset } from "./preset.service.js";
import { DEFAULT_PROFILE } from "./profile.service.js";
import {
  BROKERED_FIELDS,
  CreateResourceBody,
  configAndSecret,
  createResource,
  MAIN_FIELD,
  purgeResources,
  type ResourceDto,
} from "./resource.service.js";
import { markHealth } from "./resource-health.service.js";
import { runDraftTest } from "./resource-test.service.js";
import { createVariable, type VariableDto } from "./variable.service.js";

const Key = z
  .string()
  .trim()
  .regex(/^[A-Z_][A-Z0-9_]*$/, "use UPPER_SNAKE_CASE");
const Extra = z.union([
  z.object({ key: Key, field: z.string() }),
  z.object({ key: Key, value: z.string().max(10_000) }),
]);

export const CreateServiceBody = z.object({
  key: Key,
  preset: z.string().optional(),
  mainField: z.string().optional(),
  extras: z.array(Extra).max(10).default([]),
  test: z.boolean().default(true),
  /** Create*Resource fields without `name` (the hidden name is derived from the key). */
  resource: z.looseObject({ kind: z.string() }),
});

export interface ServiceCreatedDto {
  service: ResourceDto;
  variables: VariableDto[];
  test: { ok: boolean; profile: string; latencyMs: number; message: string } | null;
}

const invalid = (path: string, message: string) =>
  new AppError("VALIDATION_FAILED", { details: [{ path, message }] });

async function uniqueName(envId: Types.ObjectId, key: string): Promise<string> {
  for (let i = 1; i < 100; i += 1) {
    const name = i === 1 ? key : `${key}-${i}`;
    if (!(await ResourceModel.exists({ environmentId: envId, name }))) return name;
  }
  throw new AppError("CONFLICT", { message: "Too many services share this name." });
}

/** D1: one admin action creates a service, its main variable and its extra keys — or nothing. */
export async function createService(
  actorId: string,
  envId: Types.ObjectId,
  input: z.infer<typeof CreateServiceBody>,
): Promise<ServiceCreatedDto> {
  await loadEnvironment(actorId, envId, "admin");
  const preset = input.preset ? getPreset(input.preset) : undefined;
  if (input.preset && !preset) throw invalid("preset", `Unknown preset "${input.preset}".`);
  if (preset && preset.kind !== input.resource.kind)
    throw invalid("resource.kind", `${preset.name} is a ${preset.kind} service.`);

  const keys = [input.key, ...input.extras.map((e) => e.key)];
  if (new Set(keys).size !== keys.length) throw invalid("extras", "Each key can be used once.");
  const taken = await VariableModel.findOne({ environmentId: envId, key: { $in: keys } }).lean();
  if (taken) throw new AppError("CONFLICT", { message: `${taken.key} already exists in this environment.` });

  const parsed = CreateResourceBody.parse({
    ...(preset?.defaults ?? {}),
    // http services remember which preset made them, so the dashboard can show "AI · OpenAI" or "Stripe".
    ...(preset && preset.kind === "http" ? { provider: preset.id } : {}),
    ...input.resource,
    name: await uniqueName(envId, input.key),
  });
  const kind = parsed.kind as ResourceKind;
  const mainField = input.mainField ?? MAIN_FIELD[kind];
  const fields = [mainField, ...input.extras.flatMap((e) => ("field" in e ? [e.field] : []))];
  for (const f of fields)
    if (!BROKERED_FIELDS[kind].includes(f))
      throw invalid("extras", `${kind} services provide: ${BROKERED_FIELDS[kind].join(", ")}`);

  let test: ServiceCreatedDto["test"] = null;
  // A webhook without a secret yet (Stripe Connect, Razorpay generated) has nothing to test.
  const pendingWebhook = kind === "webhook" && !configAndSecret(kind, parsed).secret;
  if (input.test && !pendingWebhook) {
    const { config, secret } = configAndSecret(kind, parsed);
    if (!secret) throw invalid("resource", "Credentials are required.");
    test = { ...(await runDraftTest(kind, secret, config)), profile: DEFAULT_PROFILE };
    if (!test.ok) throw new AppError("SERVICE_TEST_FAILED", { message: test.message });
  }

  const service = await createResource(actorId, envId, parsed, { touch: false });
  // B11: a passing Save & test is the first proof the provider accepts the key.
  if (test?.ok) {
    await markHealth(service.id, { status: "ok" });
    service.health = { status: "ok", reason: null, checkedAt: new Date().toISOString() };
  }
  try {
    const variables: VariableDto[] = [
      await createVariable(
        actorId,
        envId,
        { type: "brokered", key: input.key, resourceId: service.id, field: mainField, required: false },
        { touch: false },
      ),
    ];
    for (const e of input.extras)
      variables.push(
        await createVariable(
          actorId,
          envId,
          "field" in e
            ? { type: "brokered", key: e.key, resourceId: service.id, field: e.field, required: false }
            : { type: "plain", key: e.key, value: e.value, resourceId: service.id, required: false },
          { touch: false },
        ),
      );
    await touchEnvironment(envId);
    return { service, variables, test };
  } catch (err) {
    // No Mongo transactions here: undo what this request created, then report the original error.
    await VariableModel.deleteMany({ resourceId: service.id });
    await purgeResources({ _id: service.id });
    throw err;
  }
}
