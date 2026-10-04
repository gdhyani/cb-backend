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
export function upstreamCa(): string[] | undefined {
  const extraCaFile = getEnv().UPSTREAM_EXTRA_CA_FILE;
  return extraCaFile ? [...tls.rootCertificates, fs.readFileSync(extraCaFile, "utf8")] : undefined;
}
