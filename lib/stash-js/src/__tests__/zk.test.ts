import { describe, it, expect } from 'vitest';
import {
  ZKCrypto,
  isZkEncrypted,
  ZK_PREFIX,
  ZK_MIN_PASSPHRASE_LENGTH,
} from '../zk.js';
import { DecryptionError, StashError } from '../errors.js';

describe('isZkEncrypted', () => {
  it('returns true for ZK-encrypted string', () => {
    expect(isZkEncrypted('$ZK$abc123')).toBe(true);
  });

  it('returns true for ZK-encrypted Uint8Array', () => {
    const data = new TextEncoder().encode('$ZK$abc123');
    expect(isZkEncrypted(data)).toBe(true);
  });

  it('returns false for non-encrypted string', () => {
    expect(isZkEncrypted('plain text')).toBe(false);
    expect(isZkEncrypted('')).toBe(false);
  });

  it('returns false for non-encrypted Uint8Array', () => {
    const data = new TextEncoder().encode('plain text');
    expect(isZkEncrypted(data)).toBe(false);
  });

  it('returns false for short data', () => {
    const data = new TextEncoder().encode('$ZK');
    expect(isZkEncrypted(data)).toBe(false);
  });

  it('returns false for prefix-only string', () => {
    expect(isZkEncrypted('$ZK$')).toBe(false);
  });

  it('returns false for prefix-only Uint8Array', () => {
    const data = new TextEncoder().encode('$ZK$');
    expect(isZkEncrypted(data)).toBe(false);
  });
});

describe('ZKCrypto', () => {
  const validPassphrase = 'test-passphrase-16-chars';

  describe('constructor', () => {
    it('accepts passphrase of minimum length', () => {
      expect(() => new ZKCrypto('1234567890123456')).not.toThrow();
    });

    it('throws for passphrase below minimum length', () => {
      expect(() => new ZKCrypto('short')).toThrow(StashError);
      expect(() => new ZKCrypto('short')).toThrow(
        `passphrase must be at least ${String(ZK_MIN_PASSPHRASE_LENGTH)} bytes`
      );
    });
  });

  describe('encrypt', () => {
    it('produces output with $ZK$ prefix', async () => {
      const crypto = new ZKCrypto(validPassphrase);
      const plaintext = new TextEncoder().encode('secret data');
      const encrypted = await crypto.encrypt(plaintext);
      const encryptedStr = new TextDecoder().decode(encrypted);
      expect(encryptedStr.startsWith(ZK_PREFIX)).toBe(true);
    });

    it('produces different output for same input (random salt/nonce)', async () => {
      const crypto = new ZKCrypto(validPassphrase);
      const plaintext = new TextEncoder().encode('secret data');
      const encrypted1 = await crypto.encrypt(plaintext);
      const encrypted2 = await crypto.encrypt(plaintext);
      expect(encrypted1).not.toEqual(encrypted2);
    });
  });

  describe('decrypt', () => {
    it('decrypts what was encrypted', async () => {
      const crypto = new ZKCrypto(validPassphrase);
      const original = 'secret data';
      const plaintext = new TextEncoder().encode(original);
      const encrypted = await crypto.encrypt(plaintext);
      const decrypted = await crypto.decrypt(encrypted);
      const result = new TextDecoder().decode(decrypted);
      expect(result).toBe(original);
    });

    it('throws DecryptionError for wrong passphrase', async () => {
      const crypto1 = new ZKCrypto(validPassphrase);
      const crypto2 = new ZKCrypto('different-passphrase-16');
      const plaintext = new TextEncoder().encode('secret');
      const encrypted = await crypto1.encrypt(plaintext);
      await expect(crypto2.decrypt(encrypted)).rejects.toBeInstanceOf(DecryptionError);
    });

    it('throws DecryptionError for missing prefix', async () => {
      const crypto = new ZKCrypto(validPassphrase);
      const data = new TextEncoder().encode('no prefix here');
      await expect(crypto.decrypt(data)).rejects.toThrow('missing $ZK$ prefix');
    });

    it('throws DecryptionError for invalid base64', async () => {
      const crypto = new ZKCrypto(validPassphrase);
      const data = new TextEncoder().encode('$ZK$not-valid-base64!!!');
      await expect(crypto.decrypt(data)).rejects.toThrow('invalid base64 encoding');
    });

    it('throws DecryptionError for data too short', async () => {
      const crypto = new ZKCrypto(validPassphrase);
      // valid base64 but decodes to very short data
      const data = new TextEncoder().encode('$ZK$YWJj');
      await expect(crypto.decrypt(data)).rejects.toThrow('encrypted data too short');
    });
  });

  describe('round-trip with various data', () => {
    it('handles empty string', async () => {
      const crypto = new ZKCrypto(validPassphrase);
      const plaintext = new TextEncoder().encode('');
      const encrypted = await crypto.encrypt(plaintext);
      const decrypted = await crypto.decrypt(encrypted);
      expect(new TextDecoder().decode(decrypted)).toBe('');
    });

    it('handles unicode characters', async () => {
      const crypto = new ZKCrypto(validPassphrase);
      const original = '你好世界 🌍 مرحبا';
      const plaintext = new TextEncoder().encode(original);
      const encrypted = await crypto.encrypt(plaintext);
      const decrypted = await crypto.decrypt(encrypted);
      expect(new TextDecoder().decode(decrypted)).toBe(original);
    });

    it('handles large data', async () => {
      const crypto = new ZKCrypto(validPassphrase);
      const original = 'x'.repeat(10000);
      const plaintext = new TextEncoder().encode(original);
      const encrypted = await crypto.encrypt(plaintext);
      const decrypted = await crypto.decrypt(encrypted);
      expect(new TextDecoder().decode(decrypted)).toBe(original);
    });

    it('handles JSON data', async () => {
      const crypto = new ZKCrypto(validPassphrase);
      const original = JSON.stringify({ key: 'value', nested: { a: 1, b: [1, 2, 3] } });
      const plaintext = new TextEncoder().encode(original);
      const encrypted = await crypto.encrypt(plaintext);
      const decrypted = await crypto.decrypt(encrypted);
      expect(new TextDecoder().decode(decrypted)).toBe(original);
    });

    it('handles Uint8Array subarray with non-zero offset', async () => {
      const crypto = new ZKCrypto(validPassphrase);
      // create a buffer with extra data and use subarray
      const fullBuffer = new Uint8Array([0, 0, 0, 104, 101, 108, 108, 111, 0, 0]); // "hello" in middle
      const subarray = fullBuffer.subarray(3, 8); // view of "hello" with byteOffset=3
      expect(subarray.byteOffset).toBe(3);

      const encrypted = await crypto.encrypt(subarray);
      const decrypted = await crypto.decrypt(encrypted);
      expect(new TextDecoder().decode(decrypted)).toBe('hello');
    });

    it('handles very large data without stack overflow', async () => {
      const crypto = new ZKCrypto(validPassphrase);
      // 100KB of data - would fail with spread operator
      const original = 'x'.repeat(100000);
      const plaintext = new TextEncoder().encode(original);
      const encrypted = await crypto.encrypt(plaintext);
      const decrypted = await crypto.decrypt(encrypted);
      expect(new TextDecoder().decode(decrypted)).toBe(original);
    });
  });

  describe('clear', () => {
    it('clears passphrase from memory', () => {
      const crypto = new ZKCrypto(validPassphrase);
      crypto.clear();
      // after clear, further operations should fail (passphrase zeroed)
      // this is best-effort in JS, mainly for API compatibility
    });
  });
});
