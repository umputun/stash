import type { ClientOptions, KeyInfo, KeyInfoResponse } from './types.js';
import { DEFAULT_OPTIONS, Format, parseKeyInfo } from './types.js';
import {
  ConnectionError,
  ForbiddenError,
  NotFoundError,
  ResponseError,
  StashError,
  UnauthorizedError,
} from './errors.js';

/**
 * HTTP client for Stash KV service.
 *
 * @example
 * ```typescript
 * const client = new Client('http://localhost:8080', { token: 'secret' });
 * await client.set('app/config', '{"debug": true}', 'json');
 * const value = await client.get('app/config');
 * ```
 */
export class Client {
  readonly #baseUrl: string;
  readonly #token: string | undefined;
  readonly #timeout: number;
  readonly #retries: number;
  readonly #zkKey: string | undefined;

  /**
   * Create a new Stash client.
   *
   * @param baseUrl - Stash server URL (e.g., "http://localhost:8080")
   * @param options - Client configuration options
   */
  constructor(baseUrl: string, options?: ClientOptions) {
    // normalize base URL (remove trailing slash)
    this.#baseUrl = baseUrl.replace(/\/+$/, '');
    this.#token = options?.token ?? undefined;
    this.#timeout = options?.timeout ?? DEFAULT_OPTIONS.timeout;
    this.#retries = options?.retries ?? DEFAULT_OPTIONS.retries;
    this.#zkKey = options?.zkKey ?? undefined;

    if (this.#zkKey !== undefined && this.#zkKey.length < 16) {
      throw new StashError('zkKey must be at least 16 characters');
    }
  }

  /**
   * Check server connectivity.
   * @throws {ConnectionError} If connection fails
   */
  async ping(): Promise<void> {
    const response = await this.#fetch('/ping');
    const text = await response.text();
    if (text !== 'pong') {
      throw new ResponseError(response.status, `unexpected ping response: ${text}`);
    }
  }

  /**
   * Get a value by key.
   *
   * @param key - Key path (e.g., "app/config")
   * @returns Value as string
   * @throws {NotFoundError} If key does not exist
   */
  async get(key: string): Promise<string> {
    const bytes = await this.getBytes(key);
    return new TextDecoder().decode(bytes);
  }

  /**
   * Get a value as raw bytes.
   *
   * @param key - Key path
   * @returns Value as Uint8Array
   * @throws {NotFoundError} If key does not exist
   */
  async getBytes(key: string): Promise<Uint8Array> {
    const response = await this.#fetch(`/kv/${this.#encodeKey(key)}`);
    const buffer = await response.arrayBuffer();
    return new Uint8Array(buffer);
  }

  /**
   * Get a value or return default if not found.
   *
   * @param key - Key path
   * @param defaultValue - Value to return if key not found
   * @returns Value or default
   */
  async getOrDefault(key: string, defaultValue: string): Promise<string> {
    try {
      return await this.get(key);
    } catch (error) {
      if (error instanceof NotFoundError) {
        return defaultValue;
      }
      throw error;
    }
  }

  /**
   * Set a value.
   *
   * @param key - Key path
   * @param value - Value to store
   * @param format - Value format for syntax highlighting (default: "text")
   */
  async set(key: string, value: string, format: Format = Format.Text): Promise<void> {
    await this.#fetch(`/kv/${this.#encodeKey(key)}`, {
      method: 'PUT',
      headers: {
        'X-Stash-Format': format,
        'Content-Type': 'text/plain',
      },
      body: value,
    });
  }

  /**
   * Delete a key.
   *
   * @param key - Key path
   * @throws {NotFoundError} If key does not exist
   */
  async delete(key: string): Promise<void> {
    await this.#fetch(`/kv/${this.#encodeKey(key)}`, {
      method: 'DELETE',
    });
  }

  /**
   * List keys with optional prefix filter.
   *
   * @param prefix - Optional prefix to filter keys (e.g., "app/")
   * @returns Array of KeyInfo objects
   */
  async list(prefix?: string): Promise<readonly KeyInfo[]> {
    const url = prefix !== undefined ? `/kv/?prefix=${encodeURIComponent(prefix)}` : '/kv/';
    const response = await this.#fetch(url);
    const data = (await response.json()) as KeyInfoResponse[];
    return data.map(parseKeyInfo);
  }

  /**
   * Get metadata for a key.
   *
   * @param key - Key path
   * @returns Key metadata
   * @throws {NotFoundError} If key does not exist
   */
  async info(key: string): Promise<KeyInfo> {
    // list with exact key as prefix, find exact match
    const keys = await this.list(key);
    const found = keys.find((k) => k.key === key);
    if (found === undefined) {
      throw new NotFoundError(key);
    }
    return found;
  }

  /**
   * Clear sensitive data from memory.
   * Call this when done with the client if using ZK encryption.
   */
  close(): void {
    // zkKey is readonly, can't be cleared in JS
    // this method exists for API compatibility with Go/Python SDKs
  }

  /**
   * Encode key for URL path, preserving slashes.
   */
  #encodeKey(key: string): string {
    return key
      .split('/')
      .map((segment) => encodeURIComponent(segment))
      .join('/');
  }

  /**
   * Make an HTTP request with retry logic.
   */
  async #fetch(path: string, init?: RequestInit): Promise<Response> {
    const url = `${this.#baseUrl}${path}`;

    const headers = new Headers(init?.headers);
    if (this.#token !== undefined) {
      headers.set('Authorization', `Bearer ${this.#token}`);
    }

    let lastError: Error | undefined;

    for (let attempt = 0; attempt <= this.#retries; attempt++) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => {
          controller.abort();
        }, this.#timeout);

        const response = await fetch(url, {
          ...init,
          headers,
          signal: controller.signal,
        });

        clearTimeout(timeoutId);

        // handle HTTP errors
        if (!response.ok) {
          this.#handleHttpError(response);
        }

        return response;
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));

        // don't retry on HTTP errors (they're thrown synchronously by #handleHttpError)
        if (error instanceof StashError) {
          throw error;
        }

        // retry on network/timeout errors
        if (attempt < this.#retries) {
          // exponential backoff: 100ms, 200ms, 400ms...
          const delay = 100 * Math.pow(2, attempt);
          await this.#sleep(delay);
        }
      }
    }

    throw new ConnectionError(lastError?.message ?? 'request failed');
  }

  /**
   * Handle HTTP error responses.
   */
  #handleHttpError(response: Response): never {
    switch (response.status) {
      case 404:
        throw new NotFoundError('resource');
      case 401:
        throw new UnauthorizedError();
      case 403:
        throw new ForbiddenError();
      default:
        throw new ResponseError(response.status);
    }
  }

  /**
   * Sleep for specified milliseconds.
   */
  async #sleep(ms: number): Promise<void> {
    return new Promise((resolve) => {
      setTimeout(resolve, ms);
    });
  }
}
