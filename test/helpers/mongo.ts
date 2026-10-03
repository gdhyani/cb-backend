import { MongoMemoryServer } from "mongodb-memory-server";

export async function startMemoryMongo(): Promise<{ uri: string; stop(): Promise<void> }> {
  const server = await MongoMemoryServer.create();
  return { uri: server.getUri("cb_test"), stop: async () => void (await server.stop()) };
}
