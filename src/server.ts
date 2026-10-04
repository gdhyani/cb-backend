import http from "node:http";
import type { Express } from "express";
import { attachTunnel, type TunnelGateway } from "./gateway/tunnel.js";

export interface AppServer {
  server: http.Server;
  gateway: TunnelGateway;
}

/** HTTP server for the REST API plus the /tunnel WebSocket gateway. */
export function createServer(app: Express): AppServer {
  const server = http.createServer(app);
  return { server, gateway: attachTunnel(server) };
}
