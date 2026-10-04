export const ERROR_CODES = {
  VALIDATION_FAILED: { statusCode: 400, message: "The request is invalid." },
  UNAUTHORIZED: { statusCode: 401, message: "Authentication is required." },
  FORBIDDEN: { statusCode: 403, message: "You do not have access to this resource." },
  INVALID_CREDENTIALS: { statusCode: 401, message: "Email or password is incorrect." },
  CSRF_REQUIRED: { statusCode: 403, message: "This request is missing its CSRF header." },
  NO_ACCESS: {
    statusCode: 403,
    message: "You don't have access to this environment. Ask an admin to grant it in the dashboard (Access).",
  },
  ENVIRONMENT_KILLED: { statusCode: 403, message: "This environment is suspended by an administrator." },
  KILLSWITCH_ACTIVE: { statusCode: 403, message: "Access is stopped by an emergency kill switch." },
  DEVICE_AUTH_PENDING: { statusCode: 400, message: "Waiting for approval in the dashboard." },
  NOT_FOUND: { statusCode: 404, message: "The requested resource was not found." },
  ROUTE_NOT_FOUND: { statusCode: 404, message: "This endpoint does not exist." },
  CONFLICT: { statusCode: 409, message: "The resource already exists or conflicts with another." },
  EMAIL_TAKEN: { statusCode: 409, message: "An account with this email already exists." },
  LAST_OWNER: { statusCode: 409, message: "An organization needs at least one owner." },
  INVITE_INVALID: { statusCode: 410, message: "This invite link is invalid, already used or expired." },
  DEVICE_CODE_EXPIRED: { statusCode: 410, message: 'This login code expired. Run "npx cb login" again.' },
  PAYLOAD_TOO_LARGE: { statusCode: 413, message: "The request body is too large." },
  RATE_LIMITED: { statusCode: 429, message: "Too many requests. Try again later." },
  INTERNAL_ERROR: { statusCode: 500, message: "Something went wrong on our side." },
  SERVICE_UNAVAILABLE: { statusCode: 503, message: "The service is temporarily unavailable." },
} as const satisfies Record<string, { statusCode: number; message: string }>;

export type ErrorCode = keyof typeof ERROR_CODES;
