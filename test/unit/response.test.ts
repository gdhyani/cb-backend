import { describe, expect, it } from "vitest";
import { buildPagination } from "../../src/utils/response.js";

describe("buildPagination", () => {
  it("computes pages and flags", () => {
    expect(buildPagination({ page: 2, pageSize: 20, total: 45 })).toEqual({
      page: 2,
      pageSize: 20,
      total: 45,
      totalPages: 3,
      hasNext: true,
      hasPrev: true,
    });
  });

  it("handles an empty result", () => {
    expect(buildPagination({ page: 1, pageSize: 20, total: 0 })).toEqual({
      page: 1,
      pageSize: 20,
      total: 0,
      totalPages: 0,
      hasNext: false,
      hasPrev: false,
    });
  });
});
