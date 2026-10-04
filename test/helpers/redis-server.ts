import { type ChildProcess, spawn } from "node:child_process";
import type { AddressInfo } from "node:net";
import net from "node:net";

async function freePort(): Promise<number> {
  const s = net.createServer();
  await new Promise<void>((r) => s.listen(0, "127.0.0.1", r));
  const { port } = s.address() as AddressInfo;
  await new Promise<void>((r) => s.close(() => r()));
  return port;
}

/** Throwaway redis-server with a password (uses the locally installed binary). */
export async function startRedis(password: string): Promise<{ port: number; uri: string; stop(): void }> {
  const port = await freePort();
  const proc: ChildProcess = spawn(
    "redis-server",
    [
      "--port",
      String(port),
      "--bind",
      "127.0.0.1",
      "--requirepass",
      password,
      "--save",
      "",
      "--appendonly",
      "no",
    ],
    { stdio: "ignore" },
  );
  for (let i = 0; i < 50; i++) {
    const ok = await new Promise<boolean>((resolve) => {
      const s = net.connect(port, "127.0.0.1", () => {
        s.end();
        resolve(true);
      });
      s.on("error", () => resolve(false));
    });
    if (ok) break;
    await new Promise((r) => setTimeout(r, 100));
  }
  return { port, uri: `redis://:${encodeURIComponent(password)}@127.0.0.1:${port}`, stop: () => proc.kill() };
}
