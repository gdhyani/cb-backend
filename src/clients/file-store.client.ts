import { type Dispatcher, request } from "undici";
import type { Env } from "../config/env.js";
import { getEnv } from "../config/env.js";
import { StoredFileModel } from "../models/stored-file.model.js";
import type { Client, ClientHealth } from "./types.js";

/**
 * Where uploaded files live (B10). Callers only ever hand it cb ciphertext (see secret-file.service.ts); the store
 * never sees a plaintext secret, so a store breach exposes nothing without MASTER_KEY.
 */
export interface FileStore {
  put(path: string, bytes: Buffer): Promise<void>;
  get(path: string): Promise<Buffer>;
  remove(paths: string[]): Promise<void>;
}

/** FILE_STORE=mongo (default): the backend's own database. */
export class MongoFileStore implements FileStore {
  async put(path: string, bytes: Buffer): Promise<void> {
    await StoredFileModel.updateOne({ path }, { $set: { data: bytes } }, { upsert: true });
  }
  async get(path: string): Promise<Buffer> {
    const doc = await StoredFileModel.findOne({ path }).lean();
    if (!doc) throw new Error(`stored file not found: ${path}`);
    return Buffer.from(doc.data.buffer ?? doc.data);
  }
  async remove(paths: string[]): Promise<void> {
    if (paths.length) await StoredFileModel.deleteMany({ path: { $in: paths } });
  }
}

/** FILE_STORE=supabase: a private Supabase Storage bucket, through its REST API with the project's secret key. */
export class SupabaseFileStore implements FileStore {
  private readonly base: string;
  constructor(private readonly opts: { url: string; key: string; bucket: string; dispatcher?: Dispatcher }) {
    this.base = opts.url.replace(/\/+$/, "");
  }

  private async call(
    method: string,
    path: string,
    body?: Buffer | string,
    extra: Record<string, string> = {},
  ) {
    const res = await request(`${this.base}${path}`, {
      method: method as "GET",
      headers: { apikey: this.opts.key, authorization: `Bearer ${this.opts.key}`, ...extra },
      body,
      dispatcher: this.opts.dispatcher,
    });
    const bytes = Buffer.from(await res.body.arrayBuffer());
    return { status: res.statusCode, bytes };
  }

  private fail(what: string, path: string, status: number): never {
    // Status and path only: the response body and the key are never part of an error (S9).
    throw new Error(`Supabase Storage ${what} ${path} failed (HTTP ${status})`);
  }

  async put(path: string, bytes: Buffer): Promise<void> {
    const r = await this.call("POST", `/storage/v1/object/${this.opts.bucket}/${path}`, bytes, {
      "content-type": "application/octet-stream",
      "x-upsert": "true",
    });
    if (r.status >= 300) this.fail("upload", path, r.status);
  }

  async get(path: string): Promise<Buffer> {
    const r = await this.call("GET", `/storage/v1/object/authenticated/${this.opts.bucket}/${path}`);
    if (r.status !== 200) this.fail("read", path, r.status);
    return r.bytes;
  }

  async remove(paths: string[]): Promise<void> {
    if (!paths.length) return;
    const r = await this.call(
      "DELETE",
      `/storage/v1/object/${this.opts.bucket}`,
      JSON.stringify({ prefixes: paths }),
      {
        "content-type": "application/json",
      },
    );
    if (r.status >= 300) this.fail("delete", paths.join(","), r.status);
  }

  /** Startup: the bucket exists and is private (created on first run). */
  async ensureBucket(): Promise<void> {
    const r = await this.call("GET", `/storage/v1/bucket/${this.opts.bucket}`);
    if (r.status === 200) return;
    const name = this.opts.bucket;
    const c = await this.call(
      "POST",
      "/storage/v1/bucket",
      JSON.stringify({ id: name, name, public: false }),
      {
        "content-type": "application/json",
      },
    );
    if (c.status >= 300) this.fail("create bucket", name, c.status);
  }
}

let store: FileStore | undefined;
let healthy: ClientHealth = "up";

export function getFileStore(): FileStore {
  if (store) return store;
  const env = getEnv();
  store =
    env.FILE_STORE === "supabase"
      ? new SupabaseFileStore({
          url: env.SUPABASE_URL as string,
          key: env.SUPABASE_SECRET_KEY as string,
          bucket: env.SUPABASE_STORAGE_BUCKET,
        })
      : new MongoFileStore();
  return store;
}

/** Tests switch stores between suites. */
export function resetFileStore(next?: FileStore): void {
  store = next;
}

export const fileStoreClient: Client = {
  name: "file-store",
  async connect(env: Env) {
    resetFileStore();
    const s = getFileStore();
    if (env.FILE_STORE === "supabase") {
      healthy = "down";
      await (s as SupabaseFileStore).ensureBucket();
    }
    healthy = "up";
  },
  async disconnect() {
    resetFileStore();
  },
  health: () => healthy,
};
