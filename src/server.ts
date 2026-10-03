import http from "node:http";
import type { Express } from "express";

/** HTTP server around the app; the /tunnel WebSocket attaches here later. */
export function createServer(app: Express): http.Server {
  return http.createServer(app);
}
