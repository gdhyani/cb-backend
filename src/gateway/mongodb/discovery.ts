import { promises as dns } from "node:dns";
import net from "node:net";
import type { Duplex } from "node:stream";
import tls from "node:tls";
import type { MongoTarget } from "../../utils/connection-uri.js";
import { connected } from "../stream-io.js";
import { UpstreamError } from "../types.js";
import { runCommand } from "./op-msg.js";

export interface HostPort {
  host: string;
  port: number;
}
export interface Resolver {
  resolveSrv(name: string): Promise<{ name: string; port: number }[]>;
  resolveTxt(name: string): Promise<string[][]>;
}
/** TXT records may only set these (MongoDB initial DNS seedlist discovery spec). */
const TXT_OPTIONS = new Set(["authSource", "replicaSet", "loadBalanced"]);

/** Seeds to try, effective options and whether to use TLS (on by default for mongodb+srv, like the drivers). */
export async function seedList(
  target: MongoTarget,
  resolver: Resolver = dns,
): Promise<{ hosts: HostPort[]; params: URLSearchParams; tls: boolean }> {
  const params = new URLSearchParams(target.params);
  const flag = (k: string) => params.get(k)?.toLowerCase();
  if (!target.srv) {
    const useTls = flag("tls") === "true" || flag("ssl") === "true";
    return { hosts: target.hosts, params, tls: useTls };
  }
  const name = target.hosts[0]?.host ?? "";
  const domain = name.split(".").slice(1).join(".");
  const records = await resolver.resolveSrv(`_mongodb._tcp.${name}`);
  if (records.length === 0) throw new UpstreamError(`mongodb+srv ${name}: no SRV records`);
  for (const r of records)
    if (!`.${r.name.toLowerCase()}`.endsWith(`.${domain.toLowerCase()}`))
      throw new UpstreamError(
        `mongodb+srv ${name}: SRV host ${r.name} is outside the cluster's domain ${domain}`,
      );
  const txt = await resolver.resolveTxt(name).catch(() => [] as string[][]);
  if (txt.length > 1) throw new UpstreamError(`mongodb+srv ${name}: more than one TXT record`);
  for (const [k, v] of new URLSearchParams((txt[0] ?? []).join("")))
    if (TXT_OPTIONS.has(k) && !params.has(k)) params.set(k, v);
  const off = flag("tls") === "false" || flag("ssl") === "false";
  return { hosts: records.map((r) => ({ host: r.name, port: r.port })), params, tls: !off };
}

async function open(seed: HostPort, useTls: boolean, ca: string[] | undefined): Promise<Duplex> {
  const socket = useTls
    ? tls.connect({
        host: seed.host,
        port: seed.port,
        servername: net.isIP(seed.host) ? undefined : seed.host,
        ca,
      })
    : net.connect({ host: seed.host, port: seed.port });
  socket.pause();
  socket.setTimeout(8000, () => socket.destroy(new Error("timed out")));
  await connected(socket, useTls ? "secureConnect" : "connect", `mongodb ${seed.host}:${seed.port}`);
  socket.setTimeout(0);
  return socket;
}

const parseHostPort = (hp: string): HostPort => {
  const i = hp.lastIndexOf(":");
  return i > 0 ? { host: hp.slice(0, i), port: Number(hp.slice(i + 1)) } : { host: hp, port: 27017 };
};

/**
 * Connects to the writable primary: asks each seed `hello` (allowed before authentication); a primary is kept,
 * a secondary points at the primary. Only the primary is used (§10.8).
 */
export async function connectPrimary(
  seeds: HostPort[],
  useTls: boolean,
  ca: string[] | undefined,
): Promise<Duplex> {
  const failures: string[] = [];
  for (const seed of seeds) {
    let socket: Duplex | undefined;
    try {
      socket = await open(seed, useTls, ca);
      const hello = await runCommand(socket, { hello: 1, $db: "admin" });
      if (hello.isWritablePrimary || hello.ismaster) return socket;
      socket.destroy();
      if (typeof hello.primary === "string") return await open(parseHostPort(hello.primary), useTls, ca);
      failures.push(`${seed.host}:${seed.port} is not primary`);
    } catch (err) {
      socket?.destroy();
      failures.push(`${seed.host}:${seed.port} ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  throw new UpstreamError(`mongodb: no reachable primary (${failures.join("; ")})`);
}
