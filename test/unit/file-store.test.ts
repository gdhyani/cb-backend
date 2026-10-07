import { Binary } from "bson";
import { MockAgent } from "undici";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MongoFileStore, SupabaseFileStore } from "../../src/clients/file-store.client.js";
import { loadEnv } from "../../src/config/env.js";
import { StoredFileModel } from "../../src/models/stored-file.model.js";
import { testEnvVars } from "../helpers/env.js";

const URL_ = "https://proj.supabase.co";
const KEY = "sb_secret_TESTKEY_123456";

function store() {
  const agent = new MockAgent();
  agent.disableNetConnect();
  const pool = agent.get(URL_);
  const seen: { method: string; path: string; headers: Record<string, string>; body?: string }[] = [];
  const record = (opts: { method: string; path: string; headers?: unknown; body?: unknown }) => {
    seen.push({
      method: opts.method,
      path: opts.path,
      headers: opts.headers as Record<string, string>,
      body: opts.body === undefined ? undefined : Buffer.from(opts.body as Uint8Array).toString(),
    });
  };
  return {
    s: new SupabaseFileStore({ url: URL_, key: KEY, bucket: "cb-files", dispatcher: agent }),
    pool,
    seen,
    record,
  };
}

describe("Supabase Storage file store (B10, S1)", () => {
  it("put uploads to the bucket path with the secret key, upsert on", async () => {
    const { s, pool, seen, record } = store();
    pool
      .intercept({ method: "POST", path: "/storage/v1/object/cb-files/orgs/o/resources/r/caCert-1.enc" })
      .reply((opts) => {
        record(opts as never);
        return { statusCode: 200, data: { Key: "x" } };
      });
    await s.put("orgs/o/resources/r/caCert-1.enc", Buffer.from("CIPHERTEXT"));
    expect(seen[0]?.headers).toMatchObject({
      apikey: KEY,
      authorization: `Bearer ${KEY}`,
      "x-upsert": "true",
    });
    expect(seen[0]?.body).toBe("CIPHERTEXT");
  });

  it("get reads the object through the authenticated route", async () => {
    const { s, pool } = store();
    pool
      .intercept({ method: "GET", path: "/storage/v1/object/authenticated/cb-files/orgs/o/a.enc" })
      .reply(200, Buffer.from("BYTES"));
    expect((await s.get("orgs/o/a.enc")).toString()).toBe("BYTES");
  });

  it("remove deletes by prefixes", async () => {
    const { s, pool, seen, record } = store();
    pool.intercept({ method: "DELETE", path: "/storage/v1/object/cb-files" }).reply((opts) => {
      record(opts as never);
      return { statusCode: 200, data: [] };
    });
    await s.remove(["orgs/o/a.enc", "orgs/o/b.enc"]);
    expect(JSON.parse(seen[0]?.body ?? "{}")).toEqual({ prefixes: ["orgs/o/a.enc", "orgs/o/b.enc"] });
  });

  it("ensureBucket creates a private bucket when it is missing", async () => {
    const { s, pool, seen, record } = store();
    pool.intercept({ method: "GET", path: "/storage/v1/bucket/cb-files" }).reply(404, { error: "not found" });
    pool.intercept({ method: "POST", path: "/storage/v1/bucket" }).reply((opts) => {
      record(opts as never);
      return { statusCode: 200, data: { name: "cb-files" } };
    });
    await s.ensureBucket();
    expect(JSON.parse(seen[0]?.body ?? "{}")).toMatchObject({
      id: "cb-files",
      name: "cb-files",
      public: false,
    });
  });

  it("a storage error names the status and path, never the key", async () => {
    const { s, pool } = store();
    pool
      .intercept({ method: "GET", path: "/storage/v1/object/authenticated/cb-files/x.enc" })
      .reply(403, { message: "denied" });
    const err = await s.get("x.enc").catch((e: Error) => e);
    expect(String(err)).toMatch(/403/);
    expect(String(err)).not.toContain(KEY);
  });
});

describe("FILE_STORE env (B10)", () => {
  it("defaults to mongo", () => {
    expect(loadEnv(testEnvVars("mongodb://x")).FILE_STORE).toBe("mongo");
  });
  it("supabase needs SUPABASE_URL and SUPABASE_SECRET_KEY", () => {
    expect(() => loadEnv({ ...testEnvVars("mongodb://x"), FILE_STORE: "supabase" })).toThrow(/SUPABASE_URL/);
    const env = loadEnv({
      ...testEnvVars("mongodb://x"),
      FILE_STORE: "supabase",
      SUPABASE_URL: URL_,
      SUPABASE_SECRET_KEY: KEY,
    });
    expect(env.SUPABASE_STORAGE_BUCKET).toBe("cb-files");
  });
});

describe("SUPABASE_URL must be https (M5, S1)", () => {
  const withUrl = (url: string) =>
    loadEnv({
      ...testEnvVars("mongodb://x"),
      FILE_STORE: "supabase",
      SUPABASE_URL: url,
      SUPABASE_SECRET_KEY: KEY,
    });

  it("M5 plain http to a remote host is refused, naming SUPABASE_URL", () => {
    expect(() => withUrl("http://proj.supabase.co")).toThrow(/SUPABASE_URL.*https/);
    expect(() => withUrl("http://10.0.0.5:54321")).toThrow(/SUPABASE_URL/);
  });

  it("M5 https anywhere and http to a loopback host (local tests) are accepted", () => {
    for (const url of [
      "https://proj.supabase.co",
      "http://localhost:54321",
      "http://127.0.0.1:54321",
      "http://[::1]:54321",
    ])
      expect(withUrl(url).SUPABASE_URL).toBe(url);
  });
});

describe("Mongo file store reads every byte form (M3, S1)", () => {
  const stub = (data: unknown) =>
    vi
      .spyOn(StoredFileModel, "findOne")
      .mockReturnValue({ lean: async () => ({ path: "p", data }) } as never);
  afterEach(() => vi.restoreAllMocks());

  it("M3 BSON Binary, Buffer and a Uint8Array view all come back as exactly the stored bytes", async () => {
    const want = "CIPHERTEXT-BYTES";
    // A Buffer and a Uint8Array that are views into a larger ArrayBuffer (as Node's pool and drivers hand out).
    const pool = Buffer.from(`xxxx${want}yyyy`);
    const forms = [
      new Binary(Buffer.from(want)),
      pool.subarray(4, 4 + want.length),
      new Uint8Array(pool.buffer, pool.byteOffset + 4, want.length),
    ];
    for (const data of forms) {
      stub(data);
      expect((await new MongoFileStore().get("p")).toString()).toBe(want);
      vi.restoreAllMocks();
    }
  });
});
