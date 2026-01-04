import type { ClientOptions, KeyInfo, KeyInfoResponse, Subscription, SubscriptionEvent } from './types.js';
import { DEFAULT_OPTIONS, Format, parseKeyInfo } from './types.js';
import {
  ConnectionError,
  ForbiddenError,
  NotFoundError,
  ResponseError,
  StashError,
  UnauthorizedError,
} from './errors.js';
import { isZkEncrypted, ZKCrypto } from './zk.js';

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
  #zkCrypto: ZKCrypto | undefined;

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

    // create ZK crypto if passphrase provided (validates length internally)
    if (options?.zkKey !== undefined) {
      this.#zkCrypto = new ZKCrypto(options.zkKey);
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
   * If ZK encryption is enabled and value is encrypted, it will be decrypted.
   *
   * @param key - Key path (e.g., "app/config")
   * @returns Value as string
   * @throws {NotFoundError} If key does not exist
   * @throws {DecryptionError} If ZK decryption fails
   */
  async get(key: string): Promise<string> {
    const bytes = await this.getBytes(key);
    return new TextDecoder().decode(bytes);
  }

  /**
   * Get a value as raw bytes.
   * If ZK encryption is enabled and value is encrypted, it will be decrypted.
   *
   * @param key - Key path
   * @returns Value as Uint8Array
   * @throws {NotFoundError} If key does not exist
   * @throws {DecryptionError} If ZK decryption fails
   */
  async getBytes(key: string): Promise<Uint8Array> {
    if (key === '') {
      throw new StashError('key cannot be empty');
    }
    const response = await this.#fetch(`/kv/${this.#encodeKey(key)}`);
    const buffer = await response.arrayBuffer();
    let data: Uint8Array = new Uint8Array(buffer);

    // decrypt if ZK crypto is configured and value is encrypted
    if (this.#zkCrypto !== undefined && isZkEncrypted(data)) {
      data = await this.#zkCrypto.decrypt(data);
    }

    return data;
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
   * If ZK encryption is enabled, the value will be encrypted before sending.
   *
   * @param key - Key path
   * @param value - Value to store
   * @param format - Value format for syntax highlighting (default: "text")
   */
  async set(key: string, value: string, format: Format = Format.Text): Promise<void> {
    if (key === '') {
      throw new StashError('key cannot be empty');
    }
    let body: string = value;

    // encrypt if ZK crypto is configured
    if (this.#zkCrypto !== undefined) {
      const plaintext = new TextEncoder().encode(value);
      const encrypted = await this.#zkCrypto.encrypt(plaintext);
      // convert to string for HTTP body (ZK format is ASCII-safe)
      body = new TextDecoder().decode(encrypted);
    }

    await this.#fetch(`/kv/${this.#encodeKey(key)}`, {
      method: 'PUT',
      headers: {
        'X-Stash-Format': format,
        'Content-Type': 'text/plain',
      },
      body,
    });
  }

  /**
   * Delete a key.
   *
   * @param key - Key path
   * @throws {NotFoundError} If key does not exist
   */
  async delete(key: string): Promise<void> {
    if (key === '') {
      throw new StashError('key cannot be empty');
    }
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
    if (key === '') {
      throw new StashError('key cannot be empty');
    }
    // list with exact key as prefix, find exact match
    const keys = await this.list(key);
    const found = keys.find((k) => k.key === key);
    if (found === undefined) {
      throw new NotFoundError(key);
    }
    return found;
  }

  /**
   * Subscribe to changes for an exact key.
   *
   * @param key - Key to monitor
   * @returns Subscription with async iterator
   *
   * @example
   * ```typescript
   * const sub = client.subscribe('app/config');
   * try {
   *   for await (const event of sub) {
   *     console.log(`${event.action}: ${event.key}`);
   *   }
   * } finally {
   *   sub.close();
   * }
   * ```
   */
  subscribe(key: string): Subscription {
    if (key === '') {
      throw new StashError('key cannot be empty');
    }
    const url = `${this.#baseUrl}/kv/subscribe/${this.#encodeKey(key)}`;
    return new SubscriptionImpl(url, this.#token);
  }

  /**
   * Subscribe to changes for all keys with a prefix.
   *
   * @param prefix - Prefix to monitor (e.g., "app" matches "app/config", "app/db")
   * @returns Subscription with async iterator
   */
  subscribePrefix(prefix: string): Subscription {
    if (prefix === '') {
      throw new StashError('prefix cannot be empty');
    }
    const url = `${this.#baseUrl}/kv/subscribe/${this.#encodeKey(prefix)}/*`;
    return new SubscriptionImpl(url, this.#token);
  }

  /**
   * Subscribe to changes for all keys.
   *
   * @returns Subscription with async iterator
   */
  subscribeAll(): Subscription {
    const url = `${this.#baseUrl}/kv/subscribe/*`;
    return new SubscriptionImpl(url, this.#token);
  }

  /**
   * Clear sensitive data from memory.
   * Call this when done with the client if using ZK encryption.
   */
  close(): void {
    if (this.#zkCrypto !== undefined) {
      this.#zkCrypto.clear();
      this.#zkCrypto = undefined;
    }
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
      const controller = new AbortController();
      const timeoutId = setTimeout(() => {
        controller.abort();
      }, this.#timeout);

      try {
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
        clearTimeout(timeoutId);
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

/**
 * Internal SSE subscription implementation with auto-reconnection.
 */
class SubscriptionImpl implements Subscription {
  readonly #url: string;
  readonly #token: string | undefined;
  #controller = new AbortController();
  #closed = false;

  constructor(url: string, token: string | undefined) {
    this.#url = url;
    this.#token = token;
  }

  async *[Symbol.asyncIterator](): AsyncGenerator<SubscriptionEvent> {
    let delay = 1000; // 1s initial

    while (!this.#closed) {
      try {
        this.#controller = new AbortController();
        const headers: Record<string, string> = {};
        if (this.#token !== undefined) {
          headers['Authorization'] = `Bearer ${this.#token}`;
        }

        const response = await fetch(this.#url, {
          headers,
          signal: this.#controller.signal,
        });

        if (!response.ok) {
          throw new Error(`HTTP ${String(response.status)}`);
        }

        const reader = response.body?.getReader();
        if (!reader) {
          throw new Error('response body is not readable');
        }

        try {
          const decoder = new TextDecoder();
          let buffer = '';
          delay = 1000; // reset on successful connection

          // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- close() modifies #closed externally
          while (!this.#closed) {
            const { done, value } = await reader.read();
            if (done) break;
            buffer += decoder.decode(value, { stream: true });

            // parse SSE events from buffer
            const lines = buffer.split('\n');
            buffer = lines.pop() ?? '';

            let eventType = '';
            let eventData = '';

            for (const line of lines) {
              if (line.startsWith('event:')) {
                eventType = line.slice(6).trim();
              } else if (line.startsWith('data:')) {
                const data = line.slice(5).trim();
                eventData = eventData === '' ? data : eventData + '\n' + data;
              } else if (line === '' && eventData !== '') {
                // end of event
                if (eventType === 'change' && eventData !== '') {
                  try {
                    const parsed = JSON.parse(eventData) as SubscriptionEvent;
                    yield parsed;
                  } catch {
                    // ignore malformed events
                  }
                }
                eventType = '';
                eventData = '';
              }
            }
          }
        } finally {
          try {
            await reader.cancel();
          } catch {
            // ignore errors during reader cancellation
          }
        }
      } catch {
        // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- close() modifies #closed externally
        if (this.#closed) break;
        await new Promise((r) => setTimeout(r, delay));
        delay = Math.min(delay * 2, 30_000); // max 30s
      }
    }
  }

  close(): void {
    this.#closed = true;
    this.#controller.abort();
  }
}
