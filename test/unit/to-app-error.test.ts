import { describe, expect, it } from "vitest";
import { z } from "zod";
import { AppError } from "../../src/errors/app-error.js";
import { ERROR_CODES } from "../../src/errors/error-codes.js";
import { toAppError } from "../../src/errors/to-app-error.js";

describe("toAppError", () => {
  it("passes AppError through and adds the controller context", () => {
    const original = new AppError("NOT_FOUND");
    const err = toAppError(original, "project.controller.get: failed to load project");
    expect(err).toBe(original);
    expect(err.context).toBe("project.controller.get: failed to load project");
  });

  it("keeps an existing context", () => {
    const err = toAppError(new AppError("NOT_FOUND", { context: "inner" }), "outer");
    expect(err.context).toBe("inner");
  });

  it("maps zod errors to VALIDATION_FAILED with details", () => {
    const result = z.object({ slug: z.string() }).safeParse({});
    const err = toAppError(result.error, "ctx");
    expect(err.code).toBe("VALIDATION_FAILED");
    expect(err.statusCode).toBe(400);
    expect(err.details?.[0]?.path).toBe("slug");
  });

  it("maps Mongo duplicate key errors to CONFLICT", () => {
    const dup = Object.assign(new Error("E11000 duplicate key"), { code: 11000 });
    const err = toAppError(dup, "ctx");
    expect(err.code).toBe("CONFLICT");
    expect(err.statusCode).toBe(409);
  });

  it("maps unknown errors to INTERNAL_ERROR with a generic message and keeps the cause", () => {
    const boom = new Error("db exploded");
    const err = toAppError(boom, "ctx");
    expect(err.code).toBe("INTERNAL_ERROR");
    expect(err.statusCode).toBe(500);
    expect(err.message).toBe(ERROR_CODES.INTERNAL_ERROR.message);
    expect(err.isOperational).toBe(false);
    expect(err.cause).toBe(boom);
  });
});
