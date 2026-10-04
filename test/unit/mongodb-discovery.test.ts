import { describe, expect, it } from "vitest";
import { AppError } from "../../src/errors/app-error.js";
import { seedList } from "../../src/gateway/mongodb/discovery.js";
import { parseMongoUri } from "../../src/utils/connection-uri.js";

const fakeDns = (srv: { name: string; port: number }[], txt: string[][] = []) => ({
  resolveSrv: async () => srv,
  resolveTxt: async () => txt,
});

describe("MongoDB URIs beyond a single host (§10.8: mongodb+srv, replica sets)", () => {
  it("parses a multi-host replica set URI", () => {
    const t = parseMongoUri(
      "mongodb://u:p%40ss@a.example.com:27017,b.example.com:27018/shop?replicaSet=rs0&authSource=admin",
    );
    expect(t.srv).toBe(false);
    expect(t.hosts).toEqual([
      { host: "a.example.com", port: 27017 },
      { host: "b.example.com", port: 27018 },
    ]);
    expect(t.password).toBe("p@ss");
    expect(t.database).toBe("shop");
    expect(t.params.get("replicaSet")).toBe("rs0");
  });

  it("parses mongodb+srv (no port allowed, one host)", () => {
    const t = parseMongoUri("mongodb+srv://u:p@cluster0.ab1cd.mongodb.net/shop?retryWrites=true");
    expect(t.srv).toBe(true);
    expect(t.hosts).toEqual([{ host: "cluster0.ab1cd.mongodb.net", port: 27017 }]);
    expect(() => parseMongoUri("mongodb+srv://u:p@cluster0.ab1cd.mongodb.net:27017/shop")).toThrow(AppError);
  });

  it("still names an out-of-range port in any host of the list", () => {
    let detail = "";
    try {
      parseMongoUri("mongodb://a:27017,b:99999/x");
    } catch (err) {
      detail = (err as AppError).details?.[0]?.message ?? "";
    }
    expect(detail).toBe("port 99999 is out of range (1–65535)");
  });

  it("resolves SRV hosts and TXT options; TLS on by default; URI options win over TXT", async () => {
    const t = parseMongoUri("mongodb+srv://u:p@cluster0.ab1cd.mongodb.net/shop?authSource=custom");
    const seeds = await seedList(
      t,
      fakeDns(
        [
          { name: "cluster0-shard-00-00.ab1cd.mongodb.net", port: 27017 },
          { name: "cluster0-shard-00-01.ab1cd.mongodb.net", port: 27017 },
        ],
        [["authSource=admin&replicaSet=atlas-xyz-shard-0"]],
      ),
    );
    expect(seeds.hosts.map((h) => h.host)).toEqual([
      "cluster0-shard-00-00.ab1cd.mongodb.net",
      "cluster0-shard-00-01.ab1cd.mongodb.net",
    ]);
    expect(seeds.tls).toBe(true);
    expect(seeds.params.get("replicaSet")).toBe("atlas-xyz-shard-0");
    expect(seeds.params.get("authSource")).toBe("custom");
  });

  it("refuses SRV results outside the cluster's domain (driver rule against DNS hijacking)", async () => {
    const t = parseMongoUri("mongodb+srv://u:p@cluster0.ab1cd.mongodb.net/shop");
    await expect(seedList(t, fakeDns([{ name: "evil.example.com", port: 27017 }]))).rejects.toThrow(/domain/);
  });

  it("tls=false on an SRV URI turns TLS off; plain multi-host follows tls/ssl", async () => {
    const off = await seedList(
      parseMongoUri("mongodb+srv://u:p@c.ab.mongodb.net/x?tls=false"),
      fakeDns([{ name: "h.ab.mongodb.net", port: 1 }]),
    );
    expect(off.tls).toBe(false);
    expect((await seedList(parseMongoUri("mongodb://a:1,b:2/x"), fakeDns([]))).tls).toBe(false);
    expect((await seedList(parseMongoUri("mongodb://a:1,b:2/x?ssl=true"), fakeDns([]))).tls).toBe(true);
  });
});
