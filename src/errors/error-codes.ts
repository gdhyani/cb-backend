export const ERROR_CODES = {
  VALIDATION_FAILED: { statusCode: 400, message: "The request is invalid." },
  UNAUTHORIZED: { statusCode: 401, message: "Authentication is required." },
  FORBIDDEN: { statusCode: 403, message: "You do not have access to this resource." },
  NOT_FOUND: { statusCode: 404, message: "The requested resource was not found." },
  ROUTE_NOT_FOUND: { statusCode: 404, message: "This endpoint does not exist." },
  CONFLICT: { statusCode: 409, message: "The resource already exists or conflicts with another." },
  PAYLOAD_TOO_LARGE: { statusCode: 413, message: "The request body is too large." },
  RATE_LIMITED: { statusCode: 429, message: "Too many requests. Try again later." },
  INTERNAL_ERROR: { statusCode: 500, message: "Something went wrong on our side." },
  SERVICE_UNAVAILABLE: { statusCode: 503, message: "The service is temporarily unavailable." },
} as const satisfies Record<string, { statusCode: number; message: string }>;

export type ErrorCode = keyof typeof ERROR_CODES;
