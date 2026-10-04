import fs from "node:fs";
import tls from "node:tls";
import { Agent } from "undici";
import { getEnv } from "../../config/env.js";

let dispatcher: Agent | undefined;

/** Shared keep-alive pool to real providers (FR-GW-009). TLS always verified (FR-GW-004). */
export function upstreamDispatcher(): Agent {
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
