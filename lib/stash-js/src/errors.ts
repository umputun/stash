/**
 * Base error class for all Stash client errors.
 */
export class StashError extends Error {
  override readonly name: string = 'StashError';

  constructor(message: string) {
    super(message);
    // restore prototype chain broken by extending built-in Error
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Key not found (HTTP 404).
 */
export class NotFoundError extends StashError {
  override readonly name = 'NotFoundError';
  readonly key: string;

  constructor(key: string) {
    super(`key not found: ${key}`);
    this.key = key;
  }
}

/**
 * Authentication required or invalid token (HTTP 401).
 */
export class UnauthorizedError extends StashError {
  override readonly name = 'UnauthorizedError';

  constructor(message = 'unauthorized') {
    super(message);
  }
}

/**
 * Insufficient permissions for the operation (HTTP 403).
 */
export class ForbiddenError extends StashError {
  override readonly name = 'ForbiddenError';

  constructor(message = 'forbidden') {
    super(message);
  }
}

/**
 * Zero-knowledge decryption failed.
 */
export class DecryptionError extends StashError {
  override readonly name = 'DecryptionError';

  constructor(message: string) {
    super(`decryption failed: ${message}`);
  }
}

/**
 * Network connection failed.
 */
export class ConnectionError extends StashError {
  override readonly name = 'ConnectionError';

  constructor(message: string) {
    super(`connection failed: ${message}`);
  }
}

/**
 * Server returned an unexpected HTTP status.
 */
export class ResponseError extends StashError {
  override readonly name = 'ResponseError';
  readonly statusCode: number;

  constructor(statusCode: number, message?: string) {
    super(message ?? `unexpected response: ${String(statusCode)}`);
    this.statusCode = statusCode;
  }
}

/**
 * Type guard to check if an error is a StashError.
 */
export function isStashError(error: unknown): error is StashError {
  return error instanceof StashError;
}

/**
 * Type guard to check if an error is a NotFoundError.
 */
export function isNotFoundError(error: unknown): error is NotFoundError {
  return error instanceof NotFoundError;
}

/**
 * Type guard to check if an error is an UnauthorizedError.
 */
export function isUnauthorizedError(error: unknown): error is UnauthorizedError {
  return error instanceof UnauthorizedError;
}

/**
 * Type guard to check if an error is a ForbiddenError.
 */
export function isForbiddenError(error: unknown): error is ForbiddenError {
  return error instanceof ForbiddenError;
}

/**
 * Type guard to check if an error is a DecryptionError.
 */
export function isDecryptionError(error: unknown): error is DecryptionError {
  return error instanceof DecryptionError;
}

/**
 * Type guard to check if an error is a ConnectionError.
 */
export function isConnectionError(error: unknown): error is ConnectionError {
  return error instanceof ConnectionError;
}

/**
 * Type guard to check if an error is a ResponseError.
 */
export function isResponseError(error: unknown): error is ResponseError {
  return error instanceof ResponseError;
}
