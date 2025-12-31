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

// zero-knowledge encryption
export {
  ZKCrypto,
  isZkEncrypted,
  ZK_PREFIX,
  ZK_SALT_SIZE,
  ZK_NONCE_SIZE,
  ZK_KEY_SIZE,
  ZK_MIN_PASSPHRASE_LENGTH,
} from './zk.js';

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
