import type { Response } from "express";

export interface Pagination {
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
  hasNext: boolean;
  hasPrev: boolean;
}

export interface ApiSuccess<T> {
  success: true;
  data: T;
  meta: { correlationId: string };
}

export interface ApiPaginated<T> {
  success: true;
  data: T[];
  meta: { correlationId: string; pagination: Pagination };
}

export function buildPagination(input: { page: number; pageSize: number; total: number }): Pagination {
  const totalPages = input.total === 0 ? 0 : Math.ceil(input.total / input.pageSize);
  return {
    page: input.page,
    pageSize: input.pageSize,
    total: input.total,
    totalPages,
    hasNext: input.page < totalPages,
    hasPrev: input.page > 1 && totalPages > 0,
  };
}

function correlationIdOf(res: Response): string {
  return String(res.locals.correlationId ?? "");
}

/** The one way controllers send data (PRD §12.7). */
export function sendSuccess<T>(res: Response, data: T, status = 200): void {
  const body: ApiSuccess<T> = { success: true, data, meta: { correlationId: correlationIdOf(res) } };
  res.status(status).json(body);
}

export function sendPaginated<T>(res: Response, items: T[], pagination: Pagination): void {
  const body: ApiPaginated<T> = {
    success: true,
    data: items,
    meta: { correlationId: correlationIdOf(res), pagination },
  };
  res.status(200).json(body);
}
