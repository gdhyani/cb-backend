import type { Express, NextFunction, Request, Response } from "express";
import request from "supertest";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { createApp } from "../../src/app.js";
import { connectMongo, disconnectMongo } from "../../src/clients/mongodb.client.js";
import { AppError } from "../../src/errors/app-error.js";
import { ERROR_CODES } from "../../src/errors/error-codes.js";
import { toAppError } from "../../src/errors/to-app-error.js";
import { logger } from "../../src/logger/logger.js";
import { startMemoryMongo } from "../helpers/mongo.js";

let mongo: Awaited<ReturnType<typeof startMemoryMongo>>;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

function testRoutes(app: Express): void {
  app.get("/api/test/boom", (_req: Request, _res: Response, next: NextFunction) => {
    try {
      throw new Error("db exploded");
    } catch (err) {
      next(toAppError(err, "test.controller.boom: failed to explode"));
    }
  });
  app.get("/api/test/missing", (_req: Request, _res: Response, next: NextFunction) => {
    try {
      throw new AppError("NOT_FOUND");
    } catch (err) {
      next(toAppError(err, "test.controller.missing: failed to find thing"));
    }
  });
}

beforeAll(async () => {
  mongo = await startMemoryMongo();
  await connectMongo(mongo.uri);
});
afterAll(async () => {
  await disconnectMongo();
  await mongo.stop();
});
afterEach(() => vi.restoreAllMocks());

describe("GET /api/health", () => {
  it("returns the success envelope with mongodb up", async () => {
    const res = await request(createApp()).get("/api/health");
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({
      success: true,
      data: { status: "ok", version: "0.0.0", checks: { mongodb: "up" } },
      meta: { correlationId: expect.stringMatching(UUID) },
    });
    expect(typeof res.body.data.uptimeSec).toBe("number");
  });
});

describe("correlation id", () => {
  it("echoes the client's id in the header and meta", async () => {
    const res = await request(createApp()).get("/api/health").set("x-correlation-id", "flow-123");
    expect(res.headers["x-correlation-id"]).toBe("flow-123");
    expect(res.body.meta.correlationId).toBe("flow-123");
  });

  it("generates a uuid when absent", async () => {
    const res = await request(createApp()).get("/api/health");
    expect(res.headers["x-correlation-id"]).toMatch(UUID);
    expect(res.body.meta.correlationId).toBe(res.headers["x-correlation-id"]);
  });
});

describe("errors", () => {
  it("unknown routes return ROUTE_NOT_FOUND in the error envelope", async () => {
    const res = await request(createApp()).get("/api/nope").set("x-correlation-id", "c-404");
    expect(res.status).toBe(404);
    expect(res.body).toEqual({
      success: false,
      error: {
        code: "ROUTE_NOT_FOUND",
        message: ERROR_CODES.ROUTE_NOT_FOUND.message,
        statusCode: 404,
        correlationId: "c-404",
      },
    });
  });

  it("unexpected errors return a generic 500 and log the stack with the controller context", async () => {
    const errorSpy = vi.spyOn(logger, "error");
    const res = await request(createApp({ extraRoutes: testRoutes })).get("/api/test/boom");
    expect(res.status).toBe(500);
    expect(res.body.error.code).toBe("INTERNAL_ERROR");
    expect(res.body.error.message).toBe(ERROR_CODES.INTERNAL_ERROR.message);
    expect(JSON.stringify(res.body)).not.toContain("db exploded");
    // winston's log methods are overloaded; read calls as plain argument lists.
    const calls = errorSpy.mock.calls as unknown as unknown[][];
    const call = calls.find(([msg]) => String(msg).includes("INTERNAL_ERROR"));
    expect(call?.[0]).toContain(
      "GET /api/test/boom → 500 INTERNAL_ERROR — test.controller.boom: failed to explode",
    );
    expect(String((call?.[1] as { stack?: string })?.stack)).toContain("db exploded");
  });

  it("operational errors log a warning without a stack", async () => {
    const warnSpy = vi.spyOn(logger, "warn");
    const res = await request(createApp({ extraRoutes: testRoutes })).get("/api/test/missing");
    expect(res.status).toBe(404);
    expect(res.body.error.code).toBe("NOT_FOUND");
    const calls = warnSpy.mock.calls as unknown as unknown[][];
    const call = calls.find(([msg]) => String(msg).includes("NOT_FOUND"));
    expect(call?.[0]).toContain(
      "GET /api/test/missing → 404 NOT_FOUND — test.controller.missing: failed to find thing",
    );
    expect(call?.[1]).toBeUndefined();
  });

  it("malformed JSON bodies return VALIDATION_FAILED", async () => {
    const res = await request(createApp())
      .post("/api/health")
      .set("content-type", "application/json")
      .send("{bad json");
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe("VALIDATION_FAILED");
  });
});
