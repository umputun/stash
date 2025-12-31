/**
 * Zero-knowledge encryption using AES-256-GCM with Argon2id key derivation.
 * Compatible with Go and Python client implementations.
 */

import { argon2id } from 'hash-wasm';
import { DecryptionError, StashError } from './errors.js';

/** ZK encrypted value prefix. */
export const ZK_PREFIX = '$ZK$' as const;

/** Salt size in bytes. */
export const ZK_SALT_SIZE = 16 as const;

/** AES-GCM nonce size in bytes. */
export const ZK_NONCE_SIZE = 12 as const;

/** AES-256 key size in bytes. */
export const ZK_KEY_SIZE = 32 as const;

/** Minimum passphrase length. */
export const ZK_MIN_PASSPHRASE_LENGTH = 16 as const;

/** GCM authentication tag size in bytes. */
export const ZK_GCM_TAG_SIZE = 16 as const;

/** Minimum encrypted data size (salt + nonce + tag). */
export const ZK_MIN_DATA_SIZE = ZK_SALT_SIZE + ZK_NONCE_SIZE + ZK_GCM_TAG_SIZE;

// Argon2id parameters (must match Go/Python implementations exactly)
const ARGON_TIME = 1;
const ARGON_MEMORY = 64 * 1024; // 64 MB in KB
const ARGON_PARALLELISM = 4;

/**
 * Check if a value is ZK-encrypted by looking for the $ZK$ prefix.
 */
export function isZkEncrypted(value: Uint8Array | string): boolean {
  // must have prefix AND some data after it (matching Go/Python behavior)
  if (typeof value === 'string') {
    return value.length > ZK_PREFIX.length && value.startsWith(ZK_PREFIX);
  }
  if (value.length <= ZK_PREFIX.length) {
    return false;
  }
  const prefix = new TextDecoder().decode(value.slice(0, ZK_PREFIX.length));
  return prefix === ZK_PREFIX;
}

/**
 * Client-side zero-knowledge encryption using AES-256-GCM with Argon2id.
 */
export class ZKCrypto {
  readonly #passphrase: Uint8Array;

  /**
   * Create a new ZKCrypto instance.
   *
   * @param passphrase - Encryption passphrase (minimum 16 bytes UTF-8)
   * @throws {StashError} If passphrase is too short
   */
  constructor(passphrase: string) {
    // use byte length for consistency with Go implementation
    const passphraseBytes = new TextEncoder().encode(passphrase);
    if (passphraseBytes.length < ZK_MIN_PASSPHRASE_LENGTH) {
      throw new StashError(
        `passphrase must be at least ${String(ZK_MIN_PASSPHRASE_LENGTH)} bytes`
      );
    }
    this.#passphrase = passphraseBytes;
  }

  /**
   * Encrypt plaintext using AES-256-GCM with Argon2id key derivation.
   *
   * Format: $ZK$<base64(salt || nonce || ciphertext || tag)>
   *
   * @param plaintext - Data to encrypt
   * @returns Encrypted data with $ZK$ prefix
   */
  async encrypt(plaintext: Uint8Array): Promise<Uint8Array> {
    // generate random salt
    const salt = crypto.getRandomValues(new Uint8Array(ZK_SALT_SIZE));

    // derive key using Argon2id
    const key = await this.#deriveKey(salt);

    // generate random nonce
    const nonce = crypto.getRandomValues(new Uint8Array(ZK_NONCE_SIZE));

    // import key for WebCrypto
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      key.buffer as ArrayBuffer,
      { name: 'AES-GCM' },
      false,
      ['encrypt']
    );

    // encrypt using AES-GCM (tag is appended to ciphertext)
    // copy to new buffer to handle Uint8Array views with non-zero byteOffset
    const plaintextCopy = new Uint8Array(plaintext);
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce },
      cryptoKey,
      plaintextCopy.buffer
    );

    // combine: salt || nonce || ciphertext (with tag)
    const combined = new Uint8Array(
      ZK_SALT_SIZE + ZK_NONCE_SIZE + ciphertext.byteLength
    );
    combined.set(salt, 0);
    combined.set(nonce, ZK_SALT_SIZE);
    combined.set(new Uint8Array(ciphertext), ZK_SALT_SIZE + ZK_NONCE_SIZE);

    // encode as base64 with prefix (iterate to avoid spread operator argument limit)
    let binary = '';
    for (const byte of combined) {
      binary += String.fromCharCode(byte);
    }
    const encoded = btoa(binary);
    return new TextEncoder().encode(ZK_PREFIX + encoded);
  }

  /**
   * Decrypt a ZK-encrypted value.
   *
   * @param encrypted - Encrypted data with $ZK$ prefix
   * @returns Decrypted plaintext
   * @throws {DecryptionError} If decryption fails
   */
  async decrypt(encrypted: Uint8Array): Promise<Uint8Array> {
    // check and remove prefix
    if (!isZkEncrypted(encrypted)) {
      throw new DecryptionError('missing $ZK$ prefix');
    }

    const encoded = new TextDecoder().decode(encrypted.slice(ZK_PREFIX.length));

    // decode base64
    let decoded: Uint8Array;
    try {
      const binary = atob(encoded);
      decoded = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        decoded[i] = binary.charCodeAt(i);
      }
    } catch {
      throw new DecryptionError('invalid base64 encoding');
    }

    // check minimum size
    if (decoded.length < ZK_MIN_DATA_SIZE) {
      throw new DecryptionError('encrypted data too short');
    }

    // extract salt, nonce, ciphertext
    const salt = decoded.slice(0, ZK_SALT_SIZE);
    const nonce = decoded.slice(ZK_SALT_SIZE, ZK_SALT_SIZE + ZK_NONCE_SIZE);
    const ciphertext = decoded.slice(ZK_SALT_SIZE + ZK_NONCE_SIZE);

    // derive key using Argon2id
    const key = await this.#deriveKey(salt);

    // import key for WebCrypto
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      key.buffer as ArrayBuffer,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );

    // decrypt using AES-GCM
    // use slice to handle Uint8Array views with non-zero byteOffset
    try {
      const plaintextBuffer = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonce },
        cryptoKey,
        ciphertext.buffer.slice(
          ciphertext.byteOffset,
          ciphertext.byteOffset + ciphertext.byteLength
        )
      );
      return new Uint8Array(plaintextBuffer);
    } catch {
      throw new DecryptionError('wrong passphrase or corrupted data');
    }
  }

  /**
   * Derive a 32-byte AES key from passphrase and salt using Argon2id.
   */
  async #deriveKey(salt: Uint8Array): Promise<Uint8Array> {
    const hash = await argon2id({
      password: this.#passphrase,
      salt,
      parallelism: ARGON_PARALLELISM,
      iterations: ARGON_TIME,
      memorySize: ARGON_MEMORY,
      hashLength: ZK_KEY_SIZE,
      outputType: 'binary',
    });
    return hash;
  }

  /**
   * Clear the passphrase from memory (best effort).
   * Note: JavaScript's garbage collector may have copied the data.
   */
  clear(): void {
    // overwrite with zeros
    this.#passphrase.fill(0);
  }
}
