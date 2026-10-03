import type { AddressInfo } from "node:net";
import net from "node:net";
import { createWebSocketStream, WebSocket } from "ws";

/** Minimal stand-in for the cb agent: a 127.0.0.1 listener that pipes every connection into its own tunnel. */
export async function localListener(serverUrl: string, token: string, params: Record<string, string>) {
  const url = new URL("/tunnel", serverUrl);
  url.protocol = "ws:";
  for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
  const closeCodes: number[] = [];
  const server = net.createServer((socket) => {
    const ws = new WebSocket(url, { headers: { authorization: `Bearer ${token}` } });
    ws.on("close", (code) => closeCodes.push(code));
    const stream = createWebSocketStream(ws);
    const kill = () => {
      socket.destroy();
      stream.destroy();
    };
    socket.on("error", kill);
    stream.on("error", kill);
    ws.on("close", () => socket.end());
    socket.pipe(stream).pipe(socket);
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return { port: (server.address() as AddressInfo).port, closeCodes, close: () => server.close() };
}
