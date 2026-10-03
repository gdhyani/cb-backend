import mongoose from "mongoose";
import type { Client, ClientHealth } from "./types.js";

export async function connectMongo(uri: string): Promise<void> {
  await mongoose.connect(uri, { serverSelectionTimeoutMS: 5_000 });
}

export async function disconnectMongo(): Promise<void> {
  await mongoose.disconnect();
}

export function mongoHealth(): ClientHealth {
  return mongoose.connection.readyState === mongoose.ConnectionStates.connected ? "up" : "down";
}

export const mongodbClient: Client = {
  name: "mongodb",
  connect: (env) => connectMongo(env.MONGODB_URI),
  disconnect: disconnectMongo,
  health: mongoHealth,
};
