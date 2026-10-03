import type { Duplex } from "node:stream";
import type { ResourceKind } from "../models/resource.model.js";

export interface TunnelContext {
  id: string;
  layer: 1 | 2;
  userId: string;
  deviceId: string;
  environmentId: string;
  projectId: string;
  orgId: string;
  resource: { id: string; kind: ResourceKind; name: string; config: Record<string, unknown> };
  /** Real credential, decrypted for this tunnel only (FR-GW-005). Never logged. */
  secret: string;
  host?: string;
  port?: number;
}

export interface AdapterHooks {
  /** Called just before a revoked tunnel closes, to send a protocol-native error (FR-GW-007). */
  onRevoke?: (reason: string) => void;
}

export type StreamAdapter = (stream: Duplex, ctx: TunnelContext, hooks: AdapterHooks) => Promise<void> | void;

/** Upstream failures surface as close code 4502 with a secret-free summary. */
export class UpstreamError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UpstreamError";
  }
}
