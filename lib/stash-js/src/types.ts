/**
 * Supported value formats for syntax highlighting.
 */
export const Format = {
  Text: 'text',
  Json: 'json',
  Yaml: 'yaml',
  Xml: 'xml',
  Toml: 'toml',
  Ini: 'ini',
  Hcl: 'hcl',
  Shell: 'shell',
} as const;

/** Union type of all supported formats. */
export type Format = (typeof Format)[keyof typeof Format];

/** Array of all valid format values for validation. */
export const VALID_FORMATS: readonly Format[] = Object.values(Format);

/**
 * Check if a value is a valid Format.
 */
export function isValidFormat(value: unknown): value is Format {
  return typeof value === 'string' && VALID_FORMATS.includes(value as Format);
}

/**
 * Metadata about a stored key.
 */
export interface KeyInfo {
  /** Key name (hierarchical with slashes, e.g., "app/config/db"). */
  readonly key: string;
  /** Size in bytes (encrypted size if ZK-encrypted). */
  readonly size: number;
  /** Value format for syntax highlighting. */
  readonly format: Format;
  /** True if key path contains "secrets" segment. */
  readonly secret: boolean;
  /** True if value is client-side ZK-encrypted. */
  readonly zkEncrypted: boolean;
  /** When the key was first created. */
  readonly createdAt: Date;
  /** When the key was last updated. */
  readonly updatedAt: Date;
}

/**
 * Raw JSON response from the server's list endpoint.
 * Uses snake_case as returned by the Go server.
 */
export interface KeyInfoResponse {
  readonly key: string;
  readonly size: number;
  readonly format: string;
  readonly secret: boolean;
  readonly zk_encrypted: boolean;
  readonly created_at: string;
  readonly updated_at: string;
}

/**
 * Parse a KeyInfoResponse from the server into a KeyInfo object.
 */
export function parseKeyInfo(response: KeyInfoResponse): KeyInfo {
  return {
    key: response.key,
    size: response.size,
    format: isValidFormat(response.format) ? response.format : Format.Text,
    secret: response.secret,
    zkEncrypted: response.zk_encrypted,
    createdAt: parseRfc3339(response.created_at),
    updatedAt: parseRfc3339(response.updated_at),
  };
}

/**
 * Parse RFC3339/RFC3339Nano timestamp from Go server.
 * Handles nanosecond precision by truncating to milliseconds.
 *
 * @example
 * parseRfc3339('2024-01-15T10:30:00.123456789Z') // Date
 */
export function parseRfc3339(timestamp: string): Date {
  // go can return up to 9 fractional digits, JS Date only supports 3
  // truncate fractional seconds to 3 digits (milliseconds)
  const normalized = timestamp.replace(
    /\.(\d{3})\d*Z$/,
    '.$1Z'
  );
  return new Date(normalized);
}

/**
 * Client configuration options.
 */
export interface ClientOptions {
  /** Bearer token for authentication. */
  readonly token?: string;
  /** Request timeout in milliseconds (default: 30000). */
  readonly timeout?: number;
  /** Number of retry attempts for failed requests (default: 3). */
  readonly retries?: number;
  /** Passphrase for zero-knowledge encryption (minimum 16 bytes UTF-8). */
  readonly zkKey?: string;
}

/** Default client options. */
export const DEFAULT_OPTIONS = {
  timeout: 30_000,
  retries: 3,
} as const;

/**
 * Event from SSE subscription.
 */
export interface SubscriptionEvent {
  /** The key that changed. */
  readonly key: string;
  /** The action: create, update, or delete. */
  readonly action: 'create' | 'update' | 'delete';
  /** RFC3339 timestamp when the change occurred. */
  readonly timestamp: string;
}

/**
 * SSE subscription with async iteration support.
 */
export interface Subscription {
  /** Async iterator for events - use with `for await...of` */
  [Symbol.asyncIterator](): AsyncIterator<SubscriptionEvent>;
  /** Terminate the subscription */
  close(): void;
}
