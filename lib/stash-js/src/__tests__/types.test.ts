import { describe, it, expect } from 'vitest';
import {
  Format,
  VALID_FORMATS,
  isValidFormat,
  parseRfc3339,
  parseKeyInfo,
  DEFAULT_OPTIONS,
  type KeyInfoResponse,
} from '../types.js';

describe('Format', () => {
  it('has all expected formats', () => {
    expect(Format.Text).toBe('text');
    expect(Format.Json).toBe('json');
    expect(Format.Yaml).toBe('yaml');
    expect(Format.Xml).toBe('xml');
    expect(Format.Toml).toBe('toml');
    expect(Format.Ini).toBe('ini');
    expect(Format.Hcl).toBe('hcl');
    expect(Format.Shell).toBe('shell');
  });

  it('VALID_FORMATS contains all formats', () => {
    expect(VALID_FORMATS).toHaveLength(8);
    expect(VALID_FORMATS).toContain('text');
    expect(VALID_FORMATS).toContain('json');
    expect(VALID_FORMATS).toContain('yaml');
  });
});

describe('isValidFormat', () => {
  it('returns true for valid formats', () => {
    expect(isValidFormat('text')).toBe(true);
    expect(isValidFormat('json')).toBe(true);
    expect(isValidFormat('yaml')).toBe(true);
  });

  it('returns false for invalid formats', () => {
    expect(isValidFormat('invalid')).toBe(false);
    expect(isValidFormat('')).toBe(false);
    expect(isValidFormat(null)).toBe(false);
    expect(isValidFormat(undefined)).toBe(false);
    expect(isValidFormat(123)).toBe(false);
  });
});

describe('parseRfc3339', () => {
  it('parses standard RFC3339 timestamp', () => {
    const date = parseRfc3339('2024-01-15T10:30:00Z');
    expect(date.toISOString()).toBe('2024-01-15T10:30:00.000Z');
  });

  it('parses RFC3339 with milliseconds', () => {
    const date = parseRfc3339('2024-01-15T10:30:00.123Z');
    expect(date.toISOString()).toBe('2024-01-15T10:30:00.123Z');
  });

  it('parses RFC3339Nano (truncates nanoseconds to milliseconds)', () => {
    const date = parseRfc3339('2024-01-15T10:30:00.123456789Z');
    expect(date.toISOString()).toBe('2024-01-15T10:30:00.123Z');
  });

  it('parses RFC3339Nano with 6 digits', () => {
    const date = parseRfc3339('2024-01-15T10:30:00.123456Z');
    expect(date.toISOString()).toBe('2024-01-15T10:30:00.123Z');
  });
});

describe('parseKeyInfo', () => {
  it('converts server response to KeyInfo', () => {
    const response: KeyInfoResponse = {
      key: 'app/config',
      size: 100,
      format: 'json',
      secret: false,
      zk_encrypted: true,
      created_at: '2024-01-15T10:30:00Z',
      updated_at: '2024-01-15T11:30:00Z',
    };

    const info = parseKeyInfo(response);

    expect(info.key).toBe('app/config');
    expect(info.size).toBe(100);
    expect(info.format).toBe('json');
    expect(info.secret).toBe(false);
    expect(info.zkEncrypted).toBe(true);
    expect(info.createdAt).toBeInstanceOf(Date);
    expect(info.updatedAt).toBeInstanceOf(Date);
  });

  it('defaults to text format for unknown formats', () => {
    const response: KeyInfoResponse = {
      key: 'test',
      size: 10,
      format: 'unknown',
      secret: false,
      zk_encrypted: false,
      created_at: '2024-01-15T10:30:00Z',
      updated_at: '2024-01-15T10:30:00Z',
    };

    const info = parseKeyInfo(response);
    expect(info.format).toBe('text');
  });
});

describe('DEFAULT_OPTIONS', () => {
  it('has expected defaults', () => {
    expect(DEFAULT_OPTIONS.timeout).toBe(30_000);
    expect(DEFAULT_OPTIONS.retries).toBe(3);
  });
});
