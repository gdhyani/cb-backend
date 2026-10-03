import { ERROR_CODES, type ErrorCode } from "./error-codes.js";

export interface ApiErrorDetail {
  path: string;
  message: string;
}

export interface ApiErrorBody {
  success: false;
  error: {
    code: string;
    message: string;
    statusCode: number;
    details?: ApiErrorDetail[];
    correlationId: string;
  };
}

export interface AppErrorOptions {
  message?: string;
  statusCode?: number;
  details?: ApiErrorDetail[];
  /** Where and what failed, e.g. "project.controller.get: failed to load project". Logs only. */
  context?: string;
  /** Original error. Logs only. */
  cause?: unknown;
  isOperational?: boolean;
}

/** The only error type that reaches API clients (PRD §12.7). */
export class AppError extends Error {
  readonly code: ErrorCode;
  readonly statusCode: number;
  readonly details?: ApiErrorDetail[];
  readonly isOperational: boolean;
  context?: string;
  override readonly cause?: unknown;

  constructor(code: ErrorCode, opts: AppErrorOptions = {}) {
    super(opts.message ?? ERROR_CODES[code].message);
    this.name = "AppError";
    this.code = code;
    this.statusCode = opts.statusCode ?? ERROR_CODES[code].statusCode;
    this.details = opts.details;
    this.context = opts.context;
    this.cause = opts.cause;
    this.isOperational = opts.isOperational ?? this.statusCode < 500;
  }

  toBody(correlationId: string): ApiErrorBody {
    return {
      success: false,
      error: {
        code: this.code,
        message: this.message,
        statusCode: this.statusCode,
        ...(this.details ? { details: this.details } : {}),
        correlationId,
      },
    };
  }
}
