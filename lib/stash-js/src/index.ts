/**
 * Stash client library for TypeScript/JavaScript.
 *
 * @example
 * ```typescript
 * import { Client, Format } from '@umputun/stash-client';
 *
 * const client = new Client('http://localhost:8080');
 * await client.set('app/config', '{"debug": true}', Format.Json);
 * const value = await client.get('app/config');
 * ```
 *
 * @packageDocumentation
 */

export { VERSION } from './version.js';

// types
export {
  Format,
  VALID_FORMATS,
  isValidFormat,
  parseRfc3339,
  parseKeyInfo,
  DEFAULT_OPTIONS,
} from './types.js';

export type {
  KeyInfo,
  KeyInfoResponse,
  ClientOptions,
} from './types.js';

// client
export { Client } from './client.js';

// errors
export {
  StashError,
  NotFoundError,
  UnauthorizedError,
  ForbiddenError,
  DecryptionError,
  ConnectionError,
  ResponseError,
  isStashError,
  isNotFoundError,
  isUnauthorizedError,
  isForbiddenError,
  isDecryptionError,
  isConnectionError,
  isResponseError,
} from './errors.js';
