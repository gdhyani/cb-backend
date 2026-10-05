import { createHash } from "node:crypto";
import fs from "node:fs";
import tls from "node:tls";
import { Agent } from "undici";
import { getEnv } from "../../config/env.js";

let dispatcher: Agent | undefined;
/** OQ9: one pool per service CA certificate (keyed by its hash), bounded. */
const withCa = new Map<string, Agent>();
const MAX_CA_POOLS = 50;

/**
 * Shared keep-alive pool to real providers (FR-GW-009). TLS always verified (FR-GW-004); a service's own CA
 * certificate (OQ9, internal APIs on a private CA) is trusted for that service's calls only.
 */
export function upstreamDispatcher(resourceCa?: unknown): Agent {
  if (typeof resourceCa === "string" && resourceCa) {
    const key = createHash("sha256").update(resourceCa).digest("hex");
    let agent = withCa.get(key);
    if (!agent) {
      if (withCa.size >= MAX_CA_POOLS) {
        const [oldest] = withCa.keys();
        if (oldest) {
          void withCa.get(oldest)?.close();
          withCa.delete(oldest);
        }
      }
      agent = new Agent({ connect: { ca: upstreamCa(resourceCa) }, keepAliveTimeout: 30_000 });
      withCa.set(key, agent);
    }
    return agent;
  }
  if (!dispatcher) {
    const extraCaFile = getEnv().UPSTREAM_EXTRA_CA_FILE;
    const ca = extraCaFile ? [...tls.rootCertificates, fs.readFileSync(extraCaFile, "utf8")] : undefined;
    dispatcher = new Agent({ connect: ca ? { ca } : {}, keepAliveTimeout: 30_000 });
  }
  return dispatcher;
}

/** Tests swap env between suites. */
export function resetUpstreamDispatcher(): void {
  void dispatcher?.close();
  dispatcher = undefined;
  for (const a of withCa.values()) void a.close();
  withCa.clear();
}

/** CA bundle for raw TLS upstreams (redis rediss://, mongodb tls=true). */
/**
 * Trusted roots for an upstream TLS connection: system roots, plus the resource's own CA certificate (self-hosted
 * or private-CA databases, production-safe) and the test-only UPSTREAM_EXTRA_CA_FILE. Undefined = system roots.
 */
export function upstreamCa(resourceCa?: unknown): string[] | undefined {
  const extraCaFile = getEnv().UPSTREAM_EXTRA_CA_FILE;
  const own = typeof resourceCa === "string" && resourceCa ? [resourceCa] : [];
  if (!extraCaFile && own.length === 0) return undefined;
  return [...tls.rootCertificates, ...(extraCaFile ? [fs.readFileSync(extraCaFile, "utf8")] : []), ...own];
}
