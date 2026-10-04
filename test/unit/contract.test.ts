import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";
import { API_PREFIX } from "../../src/constants.js";

const root = fileURLToPath(new URL("../../", import.meta.url));
const routesDir = `${root}src/routes/`;
const METHODS = ["get", "post", "put", "patch", "delete"] as const;

interface Operation {
  operationId?: string;
  security?: unknown[];
  responses?: Record<string, unknown>;
}
type Contract = {
  openapi: string;
  "x-contract-version"?: unknown;
  info: { title: string };
  paths: Record<string, Partial<Record<(typeof METHODS)[number], Operation>>>;
};

const contract = parse(readFileSync(`${root}contracts/openapi.yaml`, "utf8")) as Contract;

const routeFiles = readdirSync(routesDir).filter((f) => f.endsWith(".routes.ts"));

/** Every Express route, statically: `<router>.<method>("/path"` under the prefix used in routes/index.ts. */
function registeredRoutes(): string[] {
  const routes: string[] = [];
  for (const file of routeFiles) {
    const source = readFileSync(`${routesDir}${file}`, "utf8");
    for (const match of source.matchAll(/\.(get|post|put|patch|delete)\("(\/[^"]+)"/g)) {
      const [, method, path] = match;
      const openApiPath = `${API_PREFIX}${path}`.replace(/:([A-Za-z0-9_]+)/g, "{$1}");
      routes.push(`${method?.toUpperCase()} ${openApiPath}`);
    }
  }
  return routes.sort();
}

function documentedRoutes(): string[] {
  return Object.entries(contract.paths)
    .flatMap(([path, item]) => METHODS.filter((m) => item[m]).map((m) => `${m.toUpperCase()} ${path}`))
    .sort();
}

function operations(): [string, Operation][] {
  return Object.entries(contract.paths).flatMap(([path, item]) =>
    METHODS.flatMap((m) => {
      const op = item[m];
      return op ? [[`${m.toUpperCase()} ${path}`, op] as [string, Operation]] : [];
    }),
  );
}

describe("contracts/openapi.yaml (PRD §12.1)", () => {
  it("is OpenAPI 3.1 with a string x-contract-version", () => {
    expect(contract.openapi).toMatch(/^3\.1\./);
    expect(contract.info.title).toBe("cb API");
    expect(typeof contract["x-contract-version"]).toBe("string");
    expect(contract["x-contract-version"]).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it("mounts every routes file under the API prefix", () => {
    const index = readFileSync(`${routesDir}index.ts`, "utf8");
    expect(index).toMatch(/app\.use\(\s*API_PREFIX,/);
    for (const file of routeFiles) expect(index).toContain(`./${file.replace(/\.ts$/, ".js")}`);
  });

  it("documents every registered route", () => {
    const documented = new Set(documentedRoutes());
    const missing = registeredRoutes().filter((r) => !documented.has(r));
    expect(missing).toEqual([]);
  });

  it("documents no route that does not exist", () => {
    const registered = new Set(registeredRoutes());
    const extra = documentedRoutes().filter((r) => !registered.has(r));
    expect(extra).toEqual([]);
  });

  it("gives every operation a unique operationId, security and a 2xx response", () => {
    const ids = new Set<string>();
    for (const [route, op] of operations()) {
      expect(op.operationId, route).toMatch(/^[a-z][A-Za-z0-9]+$/);
      expect(ids.has(op.operationId ?? ""), `${route} duplicate operationId`).toBe(false);
      ids.add(op.operationId ?? "");
      expect(Array.isArray(op.security), `${route} security`).toBe(true);
      expect(
        Object.keys(op.responses ?? {}).some((c) => /^2\d\d$/.test(c)),
        `${route} 2xx`,
      ).toBe(true);
    }
  });

  it("never exposes write-only credential fields in a response schema (S2, L15)", () => {
    const schemas = (contract as unknown as { components: { schemas: Record<string, unknown> } }).components
      .schemas;
    const writeOnlyHolders = Object.entries(schemas)
      .filter(([, s]) => JSON.stringify(s).includes('"writeOnly":true'))
      .map(([name]) => name);
    const responses = JSON.stringify(operations().map(([, op]) => op.responses));
    for (const name of writeOnlyHolders) expect(responses).not.toContain(`/schemas/${name}"`);
    expect(responses).not.toContain('"writeOnly":true');
  });
});
