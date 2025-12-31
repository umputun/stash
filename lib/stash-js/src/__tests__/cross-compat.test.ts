/**
 * Cross-compatibility tests between TypeScript, Python, and Go implementations.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, writeFileSync, mkdirSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import {
  ZKCrypto,
  ZK_PREFIX,
  ZK_SALT_SIZE,
  ZK_NONCE_SIZE,
  ZK_KEY_SIZE,
  ZK_MIN_PASSPHRASE_LENGTH,
} from '../zk.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, 'fixtures');
const PASSPHRASE = 'cross-compat-key-16';

describe('CrossCompatibility', () => {
  describe('decrypt Go fixture', () => {
    it('decrypts data encrypted by Go implementation', async () => {
      const encryptedPath = join(FIXTURES_DIR, 'go_encrypted.bin');
      const plaintextPath = join(FIXTURES_DIR, 'go_plaintext.txt');

      let encrypted: Uint8Array;
      let expectedPlaintext: string;
      try {
        encrypted = readFileSync(encryptedPath);
        expectedPlaintext = readFileSync(plaintextPath, 'utf8');
      } catch {
        // skip if fixtures don't exist
        console.log('Go fixture not found, skipping');
        return;
      }

      const zk = new ZKCrypto(PASSPHRASE);
      const decrypted = await zk.decrypt(encrypted);
      const result = new TextDecoder().decode(decrypted);

      expect(result).toBe(expectedPlaintext);
    });
  });

  describe('decrypt Python fixture', () => {
    it('decrypts data encrypted by Python implementation', async () => {
      const encryptedPath = join(FIXTURES_DIR, 'python_encrypted.bin');
      const plaintextPath = join(FIXTURES_DIR, 'python_plaintext.txt');

      let encrypted: Uint8Array;
      let expectedPlaintext: string;
      try {
        encrypted = readFileSync(encryptedPath);
        expectedPlaintext = readFileSync(plaintextPath, 'utf8');
      } catch {
        // skip if fixtures don't exist
        console.log('Python fixture not found, skipping');
        return;
      }

      const zk = new ZKCrypto(PASSPHRASE);
      const decrypted = await zk.decrypt(encrypted);
      const result = new TextDecoder().decode(decrypted);

      expect(result).toBe(expectedPlaintext);
    });
  });

  describe('generate fixture for Go/Python', () => {
    it('generates encrypted data for Go/Python to decrypt', async () => {
      const plaintext = 'hello from TypeScript! 🚀';

      const zk = new ZKCrypto(PASSPHRASE);
      const encrypted = await zk.encrypt(new TextEncoder().encode(plaintext));

      // write fixtures for Go/Python tests
      mkdirSync(FIXTURES_DIR, { recursive: true });
      writeFileSync(join(FIXTURES_DIR, 'typescript_encrypted.bin'), encrypted);
      writeFileSync(join(FIXTURES_DIR, 'typescript_plaintext.txt'), plaintext);

      // verify we can decrypt our own data
      const decrypted = await zk.decrypt(encrypted);
      expect(new TextDecoder().decode(decrypted)).toBe(plaintext);
    });
  });
});

describe('Argon2Parameters', () => {
  it('verifies key derivation parameters match Go/Python', () => {
    // these must match Go/Python constants
    expect(ZK_SALT_SIZE).toBe(16);
    expect(ZK_NONCE_SIZE).toBe(12);
    expect(ZK_KEY_SIZE).toBe(32);
    expect(ZK_MIN_PASSPHRASE_LENGTH).toBe(16);
  });

  it('verifies crypto constants match Go/Python', () => {
    expect(ZK_PREFIX).toBe('$ZK$');
    // GCM tag size is 16 bytes (implicitly verified via successful decryption)
  });
});
