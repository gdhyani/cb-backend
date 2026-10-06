import { fileStoreClient } from "./file-store.client.js";
import { mongodbClient } from "./mongodb.client.js";
import type { Client } from "./types.js";

/** Connected in this order at startup, disconnected in reverse at shutdown. */
export const clients: Client[] = [mongodbClient, fileStoreClient];
