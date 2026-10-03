import { describe, expect, it } from "vitest";
import { AppError } from "../../src/errors/app-error.js";
import { ERROR_CODES } from "../../src/errors/error-codes.js";

describe("AppError", () => {
  it("takes default status and message from the catalog", () => {
    const err = new AppError("NOT_FOUND");
    expect(err.statusCode).toBe(404);
    expect(err.message).toBe(ERROR_CODES.NOT_FOUND.message);
    expect(err.isOperational).toBe(true);
  });

  it("marks 5xx errors as non-operational by default", () => {
    expect(new AppError("INTERNAL_ERROR").isOperational).toBe(false);
    expect(new AppError("SERVICE_UNAVAILABLE", { isOperational: true }).isOperational).toBe(true);
  });

  it("serializes to the error envelope without context or cause", () => {
    const err = new AppError("VALIDATION_FAILED", {
      message: "Invalid project",
      details: [{ path: "slug", message: "Required" }],
      context: "project.controller.create: invalid body",
      cause: new Error("secret internals"),
    });
    const body = err.toBody("corr-1");
    expect(body).toEqual({
      success: false,
      error: {
        code: "VALIDATION_FAILED",
        message: "Invalid project",
        statusCode: 400,
        details: [{ path: "slug", message: "Required" }],
        correlationId: "corr-1",
      },
    });
    expect(JSON.stringify(body)).not.toContain("secret internals");
    expect(JSON.stringify(body)).not.toContain("project.controller");
  });
});
