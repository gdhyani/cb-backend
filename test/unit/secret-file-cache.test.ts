import { Types } from "mongoose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type FileStore, resetFileStore } from "../../src/clients/file-store.client.js";
import {
  readSecretFile,
  SECRET_FILE_CACHE_MAX,
  saveSecretFile,
  secretFileCacheSize,
} from "../../src/services/secret-file.service.js";
import { useTestEnv } from "../helpers/env.js";

/** In-memory store that counts reads, so a cache hit is visible. */
function memoryStore() {
  const files = new Map<string, Buffer>();
  const s = {
    reads: 0,
    async put(path: string, bytes: Buffer) {
      files.set(path, Buffer.from(bytes));
    },
    async get(path: string) {
      s.reads++;
      const b = files.get(path);
      if (!b) throw new Error("missing");
      return b;
    },
    async remove(paths: string[]) {
      for (const p of paths) files.delete(p);
    },
  };
  return s satisfies FileStore;
}

describe("secret-file ciphertext cache (M4, B10)", () => {
  beforeAll(() => useTestEnv());
  afterAll(() => resetFileStore());

  it("M4 the cache never holds more than its cap and still serves every file correctly", async () => {
    const store = memoryStore();
    resetFileStore(store);
    const org = new Types.ObjectId();
    const res = new Types.ObjectId();
    const refs = [];
    for (let i = 0; i < SECRET_FILE_CACHE_MAX + 25; i++)
      refs.push(await saveSecretFile(org, res, "credentials", `value-${i}`));
    expect(secretFileCacheSize()).toBeLessThanOrEqual(SECRET_FILE_CACHE_MAX);
    // An evicted entry is read back from the store; the newest is still a cache hit.
    expect(await readSecretFile(refs[0] as (typeof refs)[number])).toBe("value-0");
    expect(store.reads).toBe(1);
    expect(await readSecretFile(refs.at(-1) as (typeof refs)[number])).toBe(
      `value-${SECRET_FILE_CACHE_MAX + 24}`,
    );
    expect(store.reads).toBe(1);
    expect(secretFileCacheSize()).toBeLessThanOrEqual(SECRET_FILE_CACHE_MAX);
  });
});
